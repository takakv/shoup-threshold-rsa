use std::fs;
use std::fs::File;
use std::io::Write;
use std::ops::{AddAssign, Sub};
use std::path::Path;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, ConcatenatingMul, RandomMod, Resize};
use der::asn1::{OctetStringRef, UintRef};
use der::Encode;
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::EncodePublicKey;
use rsa::{BigUint, RsaPublicKey};

use crate::asn1::{ShamirSecretShare, ShoupKeyShare, ShoupVerificationKey, ShoupVerifyShare};
use crate::ThresholdParameters;

const PUB_EXP: u32 = u16::MAX as u32 + 2;

fn gen_safe_prime(bits: i32) -> Result<BigNum, ErrorStack> {
    let mut bn = BigNum::new()?;
    bn.generate_prime(bits, true, None, None)?;
    Ok(bn)
}

pub fn generate(
    bits: u32,
    params: &ThresholdParameters,
    pub_path: impl AsRef<Path>,
    shares_dir: impl AsRef<Path>,
    vk_dir: impl AsRef<Path>,
) {
    eprintln!("Generating {}-bit RSA key...", bits);
    let prime_bits = (bits / 2) as i32;

    let q_thread = std::thread::spawn(move || gen_safe_prime(prime_bits).unwrap());
    let p = gen_safe_prime(prime_bits).unwrap();
    let q = q_thread.join().unwrap();

    let p = BoxedUint::from_be_slice(&p.to_vec(), bits / 2).unwrap();
    let q = BoxedUint::from_be_slice(&q.to_vec(), bits / 2).unwrap();

    assert_ne!(&p, &q);

    let pp = p.clone().sub(BoxedUint::one()).shr(1);
    let qq = q.clone().sub(BoxedUint::one()).shr(1);

    let n = p.concatenating_mul(&q).to_odd().unwrap();
    let m = pp.concatenating_mul(&qq).to_odd().unwrap();

    let e = BoxedUint::from(PUB_EXP).resize(m.bits_precision());
    let d = e.invert_odd_mod(&m).unwrap();

    let mp_n = BoxedMontyParams::new(n.clone());
    let mp_m = BoxedMontyParams::new(m.clone());

    let v = BoxedUint::random_mod_vartime(&mut rand::rng(), n.as_nz_ref());
    let v = v.mul_mod(&v, n.as_nz_ref());

    RsaPublicKey::new(
        BigUint::from_slice_native(n.as_words()),
        BigUint::from(PUB_EXP),
    )
    .unwrap()
    .write_public_key_pem_file(pub_path, LineEnding::LF)
    .expect("Failed to write public key");

    let svk_bytes = v.to_be_bytes();
    let svk_der = ShoupVerificationKey {
        vk: UintRef::new(svk_bytes.as_ref()).unwrap(),
    }
    .to_der()
    .unwrap();

    let mut svk_file = File::create("vk.der").unwrap();
    svk_file
        .write_all(&svk_der)
        .expect("Failed to write share verification");

    let monty_v = BoxedMontyForm::new(v, &mp_n);

    let threshold = params.threshold as usize;
    let mut coefficients = Vec::with_capacity(threshold);
    let mut indices = Vec::with_capacity(threshold);

    coefficients.push(BoxedMontyForm::new(d, &mp_m));
    indices.push(BoxedUint::zero().resize(m.bits_precision()));

    for i in 1..threshold as u32 {
        let tmp = BoxedUint::random_mod_vartime(&mut rand::rng(), m.as_nz_ref());
        coefficients.push(BoxedMontyForm::new(tmp, &mp_m));
        indices.push(BoxedUint::from(i).resize(m.bits_precision()));
    }

    let shares_dir = shares_dir.as_ref();
    let vk_dir = vk_dir.as_ref();
    fs::create_dir_all(shares_dir).expect("Failed to create shares dir");
    fs::create_dir_all(vk_dir).expect("Failed to create vk dir");

    let n_bytes = n.to_be_bytes();
    let e_bytes = e.to_be_bytes();

    let n_ref = UintRef::new(&n_bytes).unwrap();
    let e_ref = UintRef::new(&e_bytes).unwrap();

    let zero = BoxedMontyForm::zero(&mp_m);
    for i in 0..params.total_shares {
        // The actual 'x' coordinate ranges from [1, total] since P(0) = d, which must not leak.
        let mi = BoxedUint::from(i as u32 + 1).resize(m.bits_precision());
        let mi = BoxedMontyForm::new(mi, &mp_m);

        let mut sum = zero.clone();
        for (idx, coeff) in indices.iter().zip(coefficients.iter()) {
            sum.add_assign(&mi.pow(idx).mul(coeff));
        }

        let index_bytes = i.to_be_bytes();
        let share_index = OctetStringRef::new(&index_bytes).unwrap();

        let count_bytes = params.total_shares.to_be_bytes();
        let share_count = OctetStringRef::new(&count_bytes).unwrap();

        let share_val = sum.retrieve();
        let secret_bytes = share_val.to_be_bytes();
        let secret = UintRef::new(secret_bytes.as_ref()).unwrap();

        // Widen from m's precision to n's; no byte round-trip needed.
        let exp = share_val.resize(n.bits_precision());
        let public_share = monty_v.pow(&exp).retrieve().to_be_bytes();

        let verify = ShoupVerifyShare {
            share_index,
            public_share: UintRef::new(public_share.as_ref()).unwrap(),
        };

        let shoup = ShoupKeyShare {
            n: n_ref,
            e: e_ref,
            d: secret,
        };

        let shoup_der_bytes = shoup.to_der().unwrap();

        let shamir = ShamirSecretShare {
            share_index,
            share_count,
            secret_share: OctetStringRef::new(&shoup_der_bytes).unwrap(),
            vk: Some(OctetStringRef::new(&svk_der).unwrap()),
        };

        let share_filename = shares_dir.join(format!("share-{}.der", i));
        let verify_filename = vk_dir.join(format!("vk-share-{}.der", i));

        let mut share_file = File::create(&share_filename).unwrap();
        share_file
            .write_all(&shamir.to_der().unwrap())
            .expect("Failed to write share");

        let mut verify_file = File::create(&verify_filename).unwrap();
        verify_file
            .write_all(&verify.to_der().unwrap())
            .expect("Failed to write share verification");
    }
}
