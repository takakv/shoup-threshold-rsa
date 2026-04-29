use std::collections::HashMap;
use std::fs;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BitOps, BoxedUint, Word};
use der::Decode;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
use rug::{integer::Order, Integer};

use crate::asn1::{
    CorrectnessProofDer, ShamirSecretShare, ShoupKeyShare, ShoupVerificationKey, ShoupVerifyShare,
    SignatureShareDer,
};
use crate::types::ShareProof;
use crate::{KeyShare, PublicParameters, SignatureShare, VerifyShare};

pub fn load_pub_params(pem_path: impl AsRef<std::path::Path>) -> PublicParameters {
    let pub_key =
        rsa::RsaPublicKey::read_public_key_pem_file(pem_path).expect("Failed to read public key");

    let n = Integer::from_digits(&pub_key.n().to_bytes_be(), Order::Msf);
    let e = Integer::from_digits(&pub_key.e().to_bytes_be(), Order::Msf);

    let n_words = n.to_digits::<Word>(Order::Lsf);
    let n_odd = BoxedUint::from_words(n_words)
        .to_odd()
        .expect("RSA modulus is not odd");
    let byte_len = n_odd.bytes_precision();
    let monty_params = BoxedMontyParams::new(n_odd);

    PublicParameters {
        n,
        e,
        byte_len,
        monty_params,
    }
}

pub fn load_key_share(
    path: impl AsRef<std::path::Path>,
) -> (KeyShare, PublicParameters, Option<BoxedMontyForm>, u16) {
    let path = path.as_ref();
    let data = fs::read(path).unwrap_or_else(|e| {
        eprintln!("error: failed to read key share {}: {}", path.display(), e);
        std::process::exit(1);
    });
    let shamir = ShamirSecretShare::from_der(&data).unwrap_or_else(|_| {
        eprintln!(
            "error: {} is not a valid or well-formed key share",
            path.display()
        );
        std::process::exit(1);
    });

    let bytes = shamir.share_index.as_bytes();
    let mut buf = [0u8; 2];
    buf[2 - bytes.len()..].copy_from_slice(bytes);
    let index = u16::from_be_bytes(buf) + 1;

    let count_bytes = shamir.share_count.as_bytes();
    let mut buf = [0u8; 2];
    buf[2 - count_bytes.len()..].copy_from_slice(count_bytes);
    let total_shares = u16::from_be_bytes(buf);

    let rsa_share = ShoupKeyShare::from_der(shamir.secret_share.as_bytes()).unwrap_or_else(|e| {
        eprintln!(
            "error: {} contains a malformed RSA share: {}",
            path.display(),
            e
        );
        std::process::exit(1);
    });

    let n = Integer::from_digits(rsa_share.n.as_bytes(), Order::Msf);
    let e = Integer::from_digits(rsa_share.e.as_bytes(), Order::Lsf);

    let n_words = n.to_digits::<Word>(Order::Lsf);
    let n_odd = BoxedUint::from_words(n_words)
        .to_odd()
        .expect("RSA modulus is not odd");
    let bits_precision = 8 * n_odd.bytes_precision() as u32;

    let monty_params = BoxedMontyParams::new(n_odd);

    let vk = shamir.vk.and_then(|vk_ref| {
        let svk = ShoupVerificationKey::from_der(vk_ref.as_bytes()).ok()?;
        let v = BoxedUint::from_be_slice(svk.vk.as_bytes(), bits_precision).ok()?;
        Some(BoxedMontyForm::new(v, monty_params.clone()))
    });

    let params = PublicParameters {
        n,
        e,
        byte_len: monty_params.bits_precision() as usize / 8,
        monty_params,
    };

    let d = BoxedUint::from_be_slice(rsa_share.d.as_bytes(), bits_precision)
        .expect("Failed to build BoxedUint");

    (KeyShare { index, d }, params, vk, total_shares)
}

pub fn load_key_shares<I>(entries: I) -> (Vec<KeyShare>, PublicParameters)
where
    I: IntoIterator<Item = std::io::Result<fs::DirEntry>>,
{
    let mut key_shares = Vec::new();
    let mut params: Option<PublicParameters> = None;
    let mut bits_precision = 0;

    for entry in entries {
        let entry = entry.expect("Invalid directory entry");
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let data = fs::read(&path).expect("Failed to read share file");
        let shamir_share =
            ShamirSecretShare::from_der(&data).expect("Failed to decode Shamir secret share");

        let bytes = shamir_share.share_index.as_bytes();
        let mut buf = [0u8; 2];
        let start = 2 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        let rsa_share = ShoupKeyShare::from_der(shamir_share.secret_share.as_bytes())
            .expect("Failed to decode RSA share");

        if params.is_none() {
            let n = Integer::from_digits(rsa_share.n.as_bytes(), Order::Msf);
            let e = Integer::from_digits(rsa_share.e.as_bytes(), Order::Lsf);

            let n_words = n.to_digits::<Word>(Order::Lsf);
            let n_odd = BoxedUint::from_words(n_words)
                .to_odd()
                .expect("RSA modulus is not odd");

            bits_precision = 8 * n_odd.bytes_precision() as u32;

            params = Some(PublicParameters {
                n,
                e,
                byte_len: n_odd.bytes_precision(),
                monty_params: BoxedMontyParams::new(n_odd),
            });
        }

        let d = BoxedUint::from_be_slice(rsa_share.d.as_bytes(), bits_precision)
            .expect("Failed to build BoxedUint");
        key_shares.push(KeyShare { index, d });
    }

    let params = params.expect("Could not parse RSA public parameters");
    (key_shares, params)
}

pub fn load_signature_shares(dir: impl AsRef<std::path::Path>) -> Vec<SignatureShare> {
    let mut shares = Vec::new();
    for entry in fs::read_dir(dir).expect("Failed to read signature shares dir") {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let data = fs::read(&path).expect("Failed to read signature share");
        let der = SignatureShareDer::from_der(&data).expect("Failed to decode signature share");

        let bytes = der.share_index.as_bytes();
        let mut buf = [0u8; 2];
        buf[2 - bytes.len()..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        let signature = Integer::from_digits(der.signature.as_bytes(), Order::Msf);

        let proof = der.proof.and_then(|p| {
            let proof_der = CorrectnessProofDer::from_der(p.as_bytes()).ok()?;
            let bits = (proof_der.z.as_bytes().len() * 8) as u32;
            let challenge = BoxedUint::from_be_slice(proof_der.c.as_bytes(), 256).ok()?;
            let response = BoxedUint::from_be_slice(proof_der.z.as_bytes(), bits).ok()?;
            Some(ShareProof {
                challenge,
                response,
            })
        });

        shares.push(SignatureShare {
            index,
            signature,
            proof,
        });
    }
    shares
}

pub fn load_verify_shares<I>(entries: I, mp: &BoxedMontyParams) -> HashMap<u16, VerifyShare>
where
    I: IntoIterator<Item = std::io::Result<fs::DirEntry>>,
{
    let mut verify_shares = HashMap::new();
    for entry in entries {
        let entry = entry.expect("Invalid directory entry");
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let data = fs::read(&path).expect("Failed to read share file");
        let verify_share =
            ShoupVerifyShare::from_der(&data).expect("Failed to decode verification share");

        let bytes = verify_share.share_index.as_bytes();
        let mut buf = [0u8; 2];
        let start = 2 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        let vk = BoxedMontyForm::new(
            BoxedUint::from_be_slice(verify_share.public_share.as_bytes(), mp.bits_precision())
                .unwrap(),
            mp.clone(),
        );

        verify_shares.insert(index, VerifyShare { index, vk });
    }

    verify_shares
}
