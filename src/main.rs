use std::{
    fs::{self},
    ops::{Mul, MulAssign},
    path::PathBuf,
};

use crypto_bigint::{BoxedUint, Word};
use rasn::types::IntegerType;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use rug::{integer::Order, ops::Pow, Integer};
use sha2::Sha256;

mod arithmetic;
mod asn1;
mod convert;
mod pss;

use arithmetic::{shoup_0_coefficient, shoup_delta};
use asn1::{ShamirSecretShare, ShoupKeyShare};
use convert::{i2osp, monty_params_from_rsa_modulus, os2ip_montgomery};
use pss::emsa_pss_encode;

pub struct KeyShare {
    pub index: u32,
    pub d: BoxedUint,
}

pub struct SignatureShare {
    pub index: u32,
    pub signature: Integer,
}

fn threshold_sign(key_shares: &[KeyShare], pk: RsaPublicKey, msg: &[u8]) -> Vec<u8> {
    let em_bits = pk.n().bits() - 1;
    let em = emsa_pss_encode::<Sha256>(&msg, em_bits);
    let m = os2ip_montgomery(&em, monty_params_from_rsa_modulus(pk.n()));

    let n = Integer::from_digits(m.params().modulus().as_words(), Order::Lsf);

    let total_shares = 5;
    let delta = shoup_delta(total_shares);

    let provable = true;

    // This is used for the constant-time exponentiation, so it must be a BoxedUInt.
    let double_delta = if provable {
        let mut dd = delta.clone().mul(2) as Integer;
        if delta < Integer::ZERO {
            dd.invert_mut(&n).unwrap();
        }
        BoxedUint::from_words(dd.to_digits::<Word>(Order::Msf))
    } else {
        BoxedUint::zero()
    };

    let mut signature_shares = Vec::with_capacity(key_shares.len());
    let mut lagrange_indices = Vec::with_capacity(key_shares.len());

    for key_share in key_shares {
        let signature = if provable {
            m.pow(&key_share.d.clone().mul(&double_delta))
        } else {
            m.pow(&key_share.d)
        };

        // There are no more secrets here, so we switch to a more performant bignum library.
        // TODO: consider whether to use Rug for everything, and use `secure_pow_mod` for RSA.
        // Not sure how different the security guarantees are...
        let signature = Integer::from_digits(signature.retrieve().as_words(), Order::Lsf);
        let index = key_share.index + 1;
        signature_shares.push(SignatureShare { index, signature });
        lagrange_indices.push(index as i64);
    }

    let mut w = Integer::from(1);
    for share in signature_shares {
        let sc = shoup_0_coefficient(share.index as i64, lagrange_indices.clone(), &delta);
        let sc = if provable { sc * 2 } else { sc };

        let term = share.signature.pow_mod(&Integer::from(sc), &n).unwrap();
        w.mul_assign(&term);
        w.modulo_mut(&n);
    }

    let shoup_exp = if provable { delta.pow(2).mul(4) } else { delta };

    let pub_exp = Integer::from_digits(&pk.e().to_bytes_le(), Order::Lsf);
    let (_, a, b) = shoup_exp.extended_gcd(pub_exp, Integer::new());

    let m = Integer::from_digits(m.retrieve().as_words(), Order::Lsf);
    let wa = w.pow_mod(&a, &n).unwrap();
    let xb = m.pow_mod(&b, &n).unwrap();

    let signature = wa.mul(&xb).modulo(&n);
    i2osp(signature, pk.size())
}

fn load_key_shares<I>(entries: I) -> Vec<KeyShare>
where
    I: IntoIterator<Item = std::io::Result<fs::DirEntry>>,
{
    let mut key_shares = Vec::new();
    for entry in entries {
        let entry = entry.expect("Invalid directory entry");
        let path = entry.path();

        if !path.is_file() {
            continue;
        };

        let data = fs::read(&path).expect("Failed to read share file");
        let shamir_share: ShamirSecretShare =
            rasn::der::decode(&data).expect("Failed to decode Shamir secret share");

        let index = {
            let bytes = &shamir_share.share_index;
            let mut buf = [0u8; 4];
            let start = 4 - bytes.len();
            buf[start..].copy_from_slice(bytes);
            u32::from_be_bytes(buf)
        };

        let rsa_share: ShoupKeyShare =
            rasn::der::decode(&shamir_share.secret_share).expect("Failed to decode RSA share");

        let (d_bytes, d_len) = rsa_share.d.to_unsigned_bytes_be();
        let d_boxed = BoxedUint::from_be_slice(d_bytes.as_ref(), (d_len * 8) as u32)
            .expect("Failed to build BoxedUint");
        key_shares.push(KeyShare { index, d: d_boxed });
    }

    key_shares
}

fn main() {
    let pub_path = PathBuf::from("pub.pem");
    let msg_path = PathBuf::from("message.txt");
    let shares_dir = PathBuf::from("shares");
    let out_path = PathBuf::from("signature.bin");

    let pub_pem_bytes = fs::read(&pub_path).expect("Failed to read public key");
    let pubkey = RsaPublicKey::from_public_key_pem(
        std::str::from_utf8(&pub_pem_bytes).expect("Failed to parse public key PEM"),
    )
    .expect("Failed to load RSA public key");

    let msg = fs::read(&msg_path).expect("Failed to read message file");

    let entries = fs::read_dir(&shares_dir).expect("Failed to list shares directory");
    let key_shares = load_key_shares(entries);

    let signature = threshold_sign(&key_shares, pubkey, &msg);
    fs::write(&out_path, &signature).expect("Failed to write signature to file");
}
