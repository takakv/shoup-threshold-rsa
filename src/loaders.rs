use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BitOps, BoxedUint, Odd, Word};
use der::Decode;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
use rug::{Integer, integer::Order};

use crate::asn1::{
    CorrectnessProofDer, ShamirSecretShare, ShoupKeyShare, ShoupVerificationKey, ShoupVerifyShare,
    SignatureShareDer,
};
use crate::types::ShareProof;
use crate::{Error, KeyShare, PublicParameters, Result, SignatureShare, VerifyShare};

fn malformed(path: &Path, reason: &'static str) -> Error {
    Error::Malformed {
        path: path.to_owned(),
        reason,
    }
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| Error::Io {
        action: "read",
        path: path.to_owned(),
        source,
    })
}

fn decode_der<'a, T: Decode<'a, Error = der::Error>>(
    data: &'a [u8],
    path: &Path,
    kind: &'static str,
) -> Result<T> {
    T::from_der(data).map_err(|source| Error::Der {
        path: path.to_owned(),
        kind,
        source,
    })
}

fn files_in(dir: &Path) -> Result<Vec<PathBuf>> {
    let io_err = |source: std::io::Error| Error::Io {
        action: "list directory",
        path: dir.to_owned(),
        source,
    };

    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(io_err)? {
        let path = entry.map_err(io_err)?.path();
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn odd_modulus(n: &Integer, path: &Path) -> Result<Odd<BoxedUint>> {
    BoxedUint::from_words(n.to_digits::<Word>(Order::Lsf))
        .to_odd()
        .into_option()
        .ok_or_else(|| malformed(path, "RSA modulus is not odd"))
}

pub fn load_pub_params(pem_path: impl AsRef<Path>) -> Result<PublicParameters> {
    let path = pem_path.as_ref();
    let pub_key =
        rsa::RsaPublicKey::read_public_key_pem_file(path).map_err(|source| Error::PublicKey {
            path: path.to_owned(),
            source,
        })?;

    let n = Integer::from_digits(&pub_key.n().to_bytes_be(), Order::Msf);
    let e = Integer::from_digits(&pub_key.e().to_bytes_be(), Order::Msf);

    let n_odd = odd_modulus(&n, path)?;
    let byte_len = n_odd.bytes_precision();
    let monty_params = BoxedMontyParams::new(n_odd);

    Ok(PublicParameters {
        n,
        e,
        byte_len,
        monty_params,
    })
}

pub fn load_key_share(
    path: impl AsRef<Path>,
) -> Result<(KeyShare, PublicParameters, Option<BoxedMontyForm>, u16)> {
    let path = path.as_ref();
    let data = read(path)?;
    let shamir: ShamirSecretShare = decode_der(&data, path, "key share")?;

    let bytes = shamir.share_index.as_bytes();
    let mut buf = [0u8; 2];
    buf[2 - bytes.len()..].copy_from_slice(bytes);
    let index = u16::from_be_bytes(buf) + 1;

    let count_bytes = shamir.share_count.as_bytes();
    let mut buf = [0u8; 2];
    buf[2 - count_bytes.len()..].copy_from_slice(count_bytes);
    let total_shares = u16::from_be_bytes(buf);

    let rsa_share: ShoupKeyShare =
        decode_der(shamir.secret_share.as_bytes(), path, "RSA key share")?;

    let n = Integer::from_digits(rsa_share.n.as_bytes(), Order::Msf);
    let e = Integer::from_digits(rsa_share.e.as_bytes(), Order::Lsf);

    let n_odd = odd_modulus(&n, path)?;
    let bits_precision = 8 * n_odd.bytes_precision() as u32;

    let monty_params = BoxedMontyParams::new(n_odd);

    let vk = shamir.vk.and_then(|vk_ref| {
        let svk = ShoupVerificationKey::from_der(vk_ref.as_bytes()).ok()?;
        let v = BoxedUint::from_be_slice(svk.vk.as_bytes(), bits_precision).ok()?;
        Some(BoxedMontyForm::new(v, &monty_params))
    });

    let params = PublicParameters {
        n,
        e,
        byte_len: monty_params.bits_precision() as usize / 8,
        monty_params,
    };

    let d = BoxedUint::from_be_slice(rsa_share.d.as_bytes(), bits_precision)
        .map_err(|_| malformed(path, "secret share is larger than the modulus"))?;

    Ok((KeyShare { index, d }, params, vk, total_shares))
}

pub fn load_key_shares(dir: impl AsRef<Path>) -> Result<(Vec<KeyShare>, PublicParameters)> {
    let dir = dir.as_ref();
    let mut key_shares = Vec::new();
    let mut params = None;

    for path in files_in(dir)? {
        let (key_share, share_params, _, _) = load_key_share(&path)?;
        params.get_or_insert(share_params);
        key_shares.push(key_share);
    }

    let params = params.ok_or_else(|| Error::NoShares {
        dir: dir.to_owned(),
    })?;
    Ok((key_shares, params))
}

pub fn load_signature_shares(dir: impl AsRef<Path>) -> Result<Vec<SignatureShare>> {
    let mut shares = Vec::new();
    for path in files_in(dir.as_ref())? {
        let data = read(&path)?;
        let der: SignatureShareDer = decode_der(&data, &path, "signature share")?;

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
    Ok(shares)
}

pub fn load_verify_shares(
    dir: impl AsRef<Path>,
    mp: &BoxedMontyParams,
) -> Result<HashMap<u16, VerifyShare>> {
    let mut verify_shares = HashMap::new();
    for path in files_in(dir.as_ref())? {
        let data = read(&path)?;
        let verify_share: ShoupVerifyShare = decode_der(&data, &path, "verification share")?;

        let bytes = verify_share.share_index.as_bytes();
        let mut buf = [0u8; 2];
        let start = 2 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        let v_i =
            BoxedUint::from_be_slice(verify_share.public_share.as_bytes(), mp.bits_precision())
                .map_err(|_| malformed(&path, "verification share is larger than the modulus"))?;
        let vk = BoxedMontyForm::new(v_i, mp);

        verify_shares.insert(index, VerifyShare { index, vk });
    }

    Ok(verify_shares)
}
