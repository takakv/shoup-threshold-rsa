use std::collections::HashMap;
use std::ops::{Mul, MulAssign};

use crypto_bigint::modular::BoxedMontyForm;
use crypto_bigint::{BoxedUint, Word};
use rand::TryRng;
use rug::integer::Order;
use rug::Integer;
use sha2::Sha256;

use crate::arithmetic::{shoup_0_coefficient, shoup_delta};
use crate::convert::{i2osp, os2ip_montgomery};
use crate::pss::emsa_pss_encode;
use crate::zkp::{prove, verify_proof};
use crate::{
    KeyShare, PublicParameters, ShareProof, SignatureShare, ThresholdParameters, VerifyShare,
};

pub fn gen_signature_share<R: TryRng>(
    key_share: &KeyShare,
    pub_params: &PublicParameters,
    msg: &[u8],
    total_shares: u16,
    vk: Option<&BoxedMontyForm>,
    rng: &mut R,
) -> (BoxedUint, Option<ShareProof>) {
    let em_bits = pub_params.n.significant_bits() - 1;
    let em = emsa_pss_encode::<Sha256, R>(msg, em_bits as usize, rng);
    let m = os2ip_montgomery(&em, pub_params.monty_params.clone());

    let delta = shoup_delta(total_shares as u32);
    let delta_boxed = BoxedUint::from_words(delta.to_digits::<Word>(Order::Msf));

    let signature = m.pow(&key_share.d.clone().mul(&delta_boxed)).square();

    let proof = vk.map(|vk| prove(&m, pub_params, &vk, &signature, &key_share.d, &delta));

    #[cfg(debug_assertions)]
    if let (Some(vk), Some(proof)) = (vk, &proof) {
        assert!(
            verify_proof(&m, vk, &vk.pow(&key_share.d), &signature, proof, &delta),
            "proof verification failed in debug check"
        );
    }

    (signature.retrieve(), proof)
}

pub fn combine_shares<R: TryRng>(
    shares: &[SignatureShare],
    msg: &[u8],
    pub_params: &PublicParameters,
    params: &ThresholdParameters,
    vk_data: Option<(&BoxedMontyForm, &HashMap<u16, VerifyShare>)>,
    rng: &mut R,
) -> Vec<u8> {
    let n = &pub_params.n;

    let em_bits = n.significant_bits() - 1;
    let em = emsa_pss_encode::<Sha256, R>(msg, em_bits as usize, rng);

    let delta = shoup_delta(params.total_shares as u32);

    let valid_shares: Vec<&SignatureShare> = if let Some((vk, share_vks)) = vk_data {
        let m_monty = os2ip_montgomery(&em, pub_params.monty_params.clone());
        shares
            .iter()
            .filter(|share| {
                let v_i = match share_vks.get(&share.index) {
                    Some(v) => v,
                    None => {
                        eprintln!(
                            "error: no verification key share for index {}, skipping",
                            share.index - 1
                        );
                        return false;
                    }
                };
                let proof = match &share.proof {
                    Some(p) => p,
                    None => {
                        eprintln!("share {}: skipping (missing proof)", share.index - 1);
                        return false;
                    }
                };
                let sig_words = share.signature.to_digits::<Word>(Order::Lsf);
                let sig_uint = BoxedUint::from_words(sig_words);
                let sig_monty = BoxedMontyForm::new(sig_uint, pub_params.monty_params.clone());
                let ok = verify_proof(&m_monty, vk, &v_i.vk, &sig_monty, proof, &delta);
                if ok {
                    eprintln!("share {}: proof ok", share.index - 1);
                } else {
                    eprintln!(
                        "error: proof verification failed for share {}",
                        share.index - 1
                    );
                }
                ok
            })
            .collect()
    } else {
        shares.iter().collect()
    };

    if valid_shares.len() < params.threshold as usize {
        eprintln!(
            "error: only {}/{} shares passed verification, below threshold of {}",
            valid_shares.len(),
            shares.len(),
            params.threshold
        );
        std::process::exit(1);
    }

    let m = Integer::from_digits(&em, Order::Msf);
    let lagrange_indices: Vec<i32> = valid_shares.iter().map(|s| s.index as i32).collect();

    let mut w = Integer::from(1u32);
    for share in &valid_shares {
        let sc = shoup_0_coefficient(share.index, &lagrange_indices, &delta) * 2;
        let term = share.signature.clone().pow_mod(&sc, n).unwrap();
        w *= &term;
        w.modulo_mut(n);
    }

    let shoup_exp = delta.square() * 4u32;
    let (_, a, b) = shoup_exp.extended_gcd(pub_params.e.clone(), Integer::new());

    let wa = w.pow_mod(&a, n).unwrap();
    let xb = m.pow_mod(&b, n).unwrap();
    let signature = (wa * xb).modulo(n);

    i2osp(signature, pub_params.byte_len)
}

pub fn threshold_sign<R: TryRng>(
    key_shares: &[KeyShare],
    pub_params: &PublicParameters,
    msg: &[u8],
    params: &ThresholdParameters,
    provable: bool,
    rng: &mut R,
) -> Vec<u8> {
    let em_bits = pub_params.n.significant_bits() - 1;
    let em = emsa_pss_encode::<Sha256, R>(msg, em_bits as usize, rng);
    let m = os2ip_montgomery(&em, pub_params.monty_params.clone());

    let n = Integer::from_digits(m.params().modulus().as_words(), Order::Lsf);

    let delta = shoup_delta(params.total_shares as u32);
    let delta_boxed = BoxedUint::from_words(delta.to_digits::<Word>(Order::Msf));

    let mut signature_shares = Vec::with_capacity(key_shares.len());
    let mut lagrange_indices = Vec::with_capacity(key_shares.len());

    let mut count = 0;
    for key_share in key_shares {
        if count >= params.threshold {
            break;
        }

        let signature = if provable {
            m.pow(&key_share.d.clone().mul(&delta_boxed)).square()
        } else {
            m.pow(&key_share.d)
        };

        // There are no more secrets here, so we switch to a more performant bignum library.
        // TODO: consider whether to use Rug for everything, and use `secure_pow_mod` for RSA.
        // Not sure how different the security guarantees are...
        let signature = Integer::from_digits(signature.retrieve().as_words(), Order::Lsf);

        let index = key_share.index;
        signature_shares.push(SignatureShare {
            index,
            signature,
            proof: None,
        });
        // Use i32 to simplify subtractions when computing the coefficients of the Lagrange polynomial.
        // u16 always fits within i32.
        lagrange_indices.push(index as i32);

        count += 1;
    }

    let mut w = Integer::from(1);
    for share in signature_shares {
        let sc = shoup_0_coefficient(share.index, &lagrange_indices, &delta);
        let sc = if provable { sc * 2 } else { sc };

        let term = share.signature.pow_mod(&Integer::from(sc), &n).unwrap();
        w.mul_assign(&term);
        w.modulo_mut(&n);
    }

    let shoup_exp = if provable {
        delta.square().mul(4)
    } else {
        delta
    };

    let (_, a, b) = shoup_exp.extended_gcd(pub_params.e.clone(), Integer::new());

    let m = Integer::from_digits(m.retrieve().as_words(), Order::Lsf);
    let wa = w.pow_mod(&a, &n).unwrap();
    let xb = m.pow_mod(&b, &n).unwrap();

    let signature = wa.mul(&xb).modulo(&n);
    i2osp(signature, pub_params.byte_len)
}
