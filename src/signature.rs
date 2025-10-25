use std::ops::{Mul, MulAssign};

use crypto_bigint::{BoxedUint, Word};
use rug::integer::Order;
use rug::Integer;
use sha2::Sha256;

use crate::arithmetic::{shoup_0_coefficient, shoup_delta};
use crate::convert::{i2osp, os2ip_montgomery};
use crate::pss::emsa_pss_encode;
use crate::zkp::{build_proof, build_proof_context};
use crate::{KeyShare, PublicParameters, SignatureShare, ThresholdParameters};

pub fn threshold_sign(
    key_shares: &[KeyShare],
    pub_params: &PublicParameters,
    msg: &[u8],
    params: &ThresholdParameters,
    provable: bool,
) -> Vec<u8> {
    let em_bits = pub_params.n.significant_bits() - 1;
    let em = emsa_pss_encode::<Sha256>(&msg, em_bits as usize);
    let m = os2ip_montgomery(&em, pub_params.monty_params.clone());

    let n = Integer::from_digits(m.params().modulus().as_words(), Order::Lsf);

    let delta = shoup_delta(params.total_shares as u32);

    // This is used for the constant-time exponentiation, so it must be a BoxedUInt.
    let double_delta = if provable {
        let dd = delta.clone().mul(2) as Integer;
        BoxedUint::from_words(dd.to_digits::<Word>(Order::Msf))
    } else {
        BoxedUint::one()
    };

    let mut signature_shares = Vec::with_capacity(key_shares.len());
    let mut lagrange_indices = Vec::with_capacity(key_shares.len());

    let proof_ctx = provable.then(|| build_proof_context(&m, &double_delta));

    let mut count = 0;
    for key_share in key_shares {
        if count >= params.threshold {
            break;
        }

        let signature = if provable {
            // It would be cleaner to square the signature here.
            // TODO: benchmark whether there is a noticeable performance drop when squaring in each loop.
            m.pow(&key_share.d.clone().mul(&double_delta))
        } else {
            m.pow(&key_share.d)
        };

        if let Some(ctx) = &proof_ctx {
            let pub_share = ctx
                .verification_shares
                .get(&key_share.index)
                .expect("missing verification share");

            let proof = build_proof(&ctx, &signature, &key_share.d, &pub_share.vk.retrieve());

            #[cfg(debug_assertions)]
            {
                let verify_provable = true;
                if verify_provable {
                    let tmp1 = ctx.verification_key.pow(&proof.response);
                    let tmp2 = pub_share.vk.pow(&proof.challenge).invert().unwrap();
                    assert_eq!(proof.key_commitment, tmp1.mul(&tmp2));

                    let tmp1 = ctx.message_witness.pow(&proof.response);
                    let tmp2 = signature.square().pow(&proof.challenge).invert().unwrap();
                    assert_eq!(proof.msg_commitment, tmp1.mul(&tmp2));
                }
            }
        }

        // There are no more secrets here, so we switch to a more performant bignum library.
        // TODO: consider whether to use Rug for everything, and use `secure_pow_mod` for RSA.
        // Not sure how different the security guarantees are...
        let signature = Integer::from_digits(signature.retrieve().as_words(), Order::Lsf);

        let index = key_share.index;
        signature_shares.push(SignatureShare { index, signature });
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
