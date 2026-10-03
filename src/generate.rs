use std::fs;
use std::path::Path;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, ConcatenatingMul, RandomMod, Resize};
use crypto_primes::hazmat::{SetBits, SmallFactorsSieveFactory};
use crypto_primes::{Flavor, is_prime, sieve_and_find};
use der::Encode;
use der::asn1::{OctetStringRef, UintRef};
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::EncodePublicKey;
use rsa::{BigUint, RsaPublicKey};

use crate::asn1::{ShamirSecretShare, ShoupKeyShare, ShoupVerificationKey, ShoupVerifyShare};
use crate::{Error, Result, ThresholdParameters};

const PUB_EXP: u32 = u16::MAX as u32 + 2;

fn gen_safe_prime(bit_length: u32) -> BoxedUint {
    let flavor = Flavor::Safe;

    let factory = SmallFactorsSieveFactory::new(flavor, bit_length, SetBits::TwoMsb).unwrap();
    sieve_and_find(&mut rand::rng(), factory, |_rng, candidate| {
        is_prime(flavor, candidate)
    })
    .unwrap()
    .expect("failed to generate a safe prime")
}

/// Evaluates `f(x) = a_0 + a_1·x + … + a_{k-1}·x^{k-1}` using Horner's method.
fn f(a: &[BoxedMontyForm], x: &BoxedMontyForm) -> BoxedMontyForm {
    let (last, rest) = a
        .split_last()
        .expect("polynomial must have at least one coefficient");
    rest.iter()
        .rev()
        .fold(last.clone(), |acc, a_i| acc * x + a_i)
}

fn write(path: &Path, data: impl AsRef<[u8]>) -> Result<()> {
    fs::write(path, data).map_err(|source| Error::Io {
        action: "write",
        path: path.to_owned(),
        source,
    })
}

fn create_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| Error::Io {
        action: "create directory",
        path: path.to_owned(),
        source,
    })
}

pub fn generate(
    bits: u32,
    params: &ThresholdParameters,
    pub_path: impl AsRef<Path>,
    shares_dir: impl AsRef<Path>,
    vk_dir: impl AsRef<Path>,
) -> Result<()> {
    eprintln!("Generating {}-bit RSA key...", bits);
    let prime_bits = bits / 2;

    let q_thread = std::thread::spawn(move || gen_safe_prime(prime_bits));
    let p = gen_safe_prime(prime_bits);
    let q = q_thread.join().unwrap();

    assert_ne!(&p, &q);

    let pp = p.wrapping_sub(&BoxedUint::one()).shr(1);
    let qq = q.wrapping_sub(&BoxedUint::one()).shr(1);

    let n = p.concatenating_mul(&q).to_odd().unwrap();
    let m = pp.concatenating_mul(&qq).to_odd().unwrap();

    let e = BoxedUint::from(PUB_EXP).resize(m.bits_precision());
    let d = e.invert_odd_mod(&m).unwrap();

    let mp_n = BoxedMontyParams::new(n.clone());
    let mp_m = BoxedMontyParams::new(m.clone());

    let v = BoxedUint::random_mod_vartime(&mut rand::rng(), n.as_nz_ref());
    let v = v.mul_mod(&v, n.as_nz_ref());

    let pub_pem = RsaPublicKey::new(
        BigUint::from_slice_native(n.as_words()),
        BigUint::from(PUB_EXP),
    )
    .unwrap()
    .to_public_key_pem(LineEnding::LF)
    .expect("a valid RSA public key can be PEM-encoded");
    write(pub_path.as_ref(), pub_pem)?;

    let svk_bytes = v.to_be_bytes();
    let svk_der = ShoupVerificationKey {
        vk: UintRef::new(svk_bytes.as_ref()).unwrap(),
    }
    .to_der()
    .unwrap();

    write(Path::new("vk.der"), &svk_der)?;

    let monty_v = BoxedMontyForm::new(v, &mp_n);

    let threshold = params.threshold as usize;
    let mut coefficients = Vec::with_capacity(threshold);

    coefficients.push(BoxedMontyForm::new(d, &mp_m));

    for _ in 1..threshold {
        let tmp = BoxedUint::random_mod_vartime(&mut rand::rng(), m.as_nz_ref());
        coefficients.push(BoxedMontyForm::new(tmp, &mp_m));
    }

    let shares_dir = shares_dir.as_ref();
    let vk_dir = vk_dir.as_ref();
    create_dir(shares_dir)?;
    create_dir(vk_dir)?;

    let n_bytes = n.to_be_bytes();
    let e_bytes = e.to_be_bytes();

    let n_ref = UintRef::new(&n_bytes).unwrap();
    let e_ref = UintRef::new(&e_bytes).unwrap();

    for i in 0..params.total_shares {
        // The actual 'x' coordinate ranges from [1, total] since P(0) = d, which must not leak.
        let mi = BoxedUint::from(i as u32 + 1).resize(m.bits_precision());
        let mi = BoxedMontyForm::new(mi, &mp_m);

        let sum = f(&coefficients, &mi);

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

        write(&share_filename, shamir.to_der().unwrap())?;
        write(&verify_filename, verify.to_der().unwrap())?;
    }

    Ok(())
}
