use std::{
    fs::{self},
    ops::{Mul, MulAssign},
    path::PathBuf,
};

use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint,
};
use rand::{rngs::OsRng, TryRngCore};
use rasn::{
    types::{IntegerType, OctetString}, AsnType, Decode, Decoder,
    Encode,
};
use rsa::{
    pkcs8::DecodePublicKey, signature::digest::{Digest, FixedOutputReset},
    traits::PublicKeyParts,
    BigUint,
    RsaPublicKey,
};
use rug::{integer::Order, Integer};
use sha2::Sha256;

#[derive(Debug, Clone, AsnType, Encode, Decode)]
pub struct ShamirSecretShare {
    pub share_index: OctetString,
    pub secret_share: OctetString,
}

#[derive(Debug, Clone, AsnType, Encode, Decode)]
pub struct ShoupKeyShare {
    pub n: rasn::types::Integer,
    pub e: rasn::types::Integer,
    pub d: rasn::types::Integer,
}

pub struct KeyShare {
    pub index: u32,
    pub d: BoxedUint,
}

pub struct SignatureShare {
    pub index: u32,
    pub signature: Integer,
}

fn i2osp(i: Integer, len: usize) -> Vec<u8> {
    let octets = &i.to_digits::<u8>(Order::Msf);
    if octets.len() > len {
        panic!("integer too large to encode in {} bytes", len);
    }

    let mut out = vec![0u8; len];
    out[len - octets.len()..].copy_from_slice(octets);
    out
}

fn mgf1<D>(seed: &[u8], mask_len: usize) -> Vec<u8>
where
    D: Digest + FixedOutputReset,
{
    let h_len = <D as Digest>::output_size();
    const MAX: usize = u32::MAX as usize + 1;

    // 1. If maskLen > 2^32 hLen, output "mask too long" and stop.
    if mask_len > h_len * MAX {
        panic!("mask too long");
    }

    let mut hasher = D::new();

    // 2. Let T be the empty octet string.
    let ceiling = (mask_len + h_len - 1) / h_len;
    let mut t = Vec::with_capacity(h_len * ceiling);

    // 3. For counter from 0 to \ceil (maskLen / hLen) - 1, do the
    //    following:
    for i in 0..ceiling as u32 {
        // A.  Convert counter to an octet string C of length 4 octets:
        //        C = I2OSP (counter, 4) .
        //
        // B. Concatenate the hash of the seed mgfSeed and C to the octet
        //    string T:
        //       T = T || Hash(mgfSeed || C) .
        Digest::update(&mut hasher, seed);
        Digest::update(&mut hasher, &i.to_be_bytes());
        t.extend_from_slice(&hasher.finalize_reset());
    }

    // 4. Output the leading maskLen octets of T as the octet string mask.
    t.truncate(mask_len);
    t
}

fn emsa_pss_encode<D>(message: &[u8], em_bits: usize) -> Vec<u8>
where
    D: Digest + FixedOutputReset,
{
    let h_len = <D as Digest>::output_size();
    let s_len = h_len; // Use the same hash function for the message and MGF1.
    let em_len = (em_bits + 7) / 8;

    // 2. Let mHash = Hash(M), an octet string of length hLen.
    let m_hash = D::new_with_prefix(message).finalize();

    // 3. If emLen < hLen + sLen + 2, output "encoding error" and stop.
    if em_len < h_len + s_len + 2 {
        panic!("encoding error");
    }

    // 4. Generate a random octet string salt of length sLen; if sLen =
    //    0, then salt is the empty string.
    let mut salt = vec![0u8; s_len];
    OsRng
        .try_fill_bytes(&mut salt)
        .expect("Could not generate PSS salt");

    // 5. Let
    //       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    //    M' is an octet string of length 8 + hLen + sLen with eight
    //    initial zero octets.
    //
    // 6. Let H = Hash(M'), an octet string of length hLen.
    let mut hasher = D::new();
    Digest::update(&mut hasher, vec![0u8; 8]);
    Digest::update(&mut hasher, m_hash);
    Digest::update(&mut hasher, salt.clone());
    let h = hasher.finalize_reset();

    // 7. Generate an octet string PS consisting of emLen - sLen - hLen
    //    - 2 zero octets.  The length of PS may be 0.
    let ps = vec![0u8; em_len - s_len - h_len - 2];
    let ps_len = ps.len();

    // 8. Let DB = PS || 0x01 || salt; DB is an octet string of length
    //    emLen - hLen - 1.
    let mut db = vec![0u8; em_len - h_len - 1];
    db[ps_len] = 0x01;
    db[ps_len + 1..].copy_from_slice(&salt);

    // 9. Let dbMask = MGF(H, emLen - hLen - 1).
    let db_mask = mgf1::<D>(&h, em_len - h_len - 1);

    // 10. Let maskedDB = DB \xor dbMask.
    let mut masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(x, y)| x ^ y).collect();

    // 11. Set the leftmost 8emLen - emBits bits of the leftmost octet
    //     in maskedDB to zero.
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits);

    // 12. Let EM = maskedDB || H || 0xbc.
    let mut em = Vec::with_capacity(em_len);
    em.extend_from_slice(&masked_db);
    em.extend_from_slice(&h);
    em.push(0xbc);

    // 13. Output EM.
    em
}

fn monty_params_from_rsa_modulus(n: &BigUint) -> BoxedMontyParams {
    let n_bytes = n.to_bytes_be();
    let n = BoxedUint::from_be_slice(&n_bytes, n.bits() as u32)
        .expect("Failed to build BoxedUint from modulus");
    let n = n.to_odd().expect("RSA modulus is not odd");
    BoxedMontyParams::new(n)
}

fn os2ip_montgomery(octets: &[u8], mp: BoxedMontyParams) -> BoxedMontyForm {
    let ui = BoxedUint::from_be_slice(octets, mp.modulus().bits())
        .expect("Failed to build BoxedUint from octets");
    BoxedMontyForm::new(ui, mp)
}

fn shoup_delta(n: i64) -> i64 {
    (1..=n).product()
}

fn lagrange_0_coefficient(current: i64, indices: Vec<i64>) -> i64 {
    let mut nominator: i64 = 1;
    let mut denominator: i64 = 1;

    for index in indices {
        if current == index {
            continue;
        }

        nominator *= index;
        denominator *= index - current;
    }

    nominator / denominator
}

fn shoup_0_coefficient(current: i64, indices: Vec<i64>, shoup_delta: i64) -> i64 {
    shoup_delta * lagrange_0_coefficient(current, indices)
}

fn threshold_sign(key_shares: &[KeyShare], pk: RsaPublicKey, msg: &[u8]) -> Vec<u8> {
    let em_bits = pk.n().bits() - 1;
    let em = emsa_pss_encode::<Sha256>(&msg, em_bits);
    let m = os2ip_montgomery(&em, monty_params_from_rsa_modulus(pk.n()));

    let mut signature_shares = Vec::with_capacity(key_shares.len());
    let mut lagrange_indices = Vec::with_capacity(key_shares.len());

    for key_share in key_shares {
        let signature = m.pow(&key_share.d);

        // There are no more secrets here, so we switch to a more performant bignum library.
        // TODO: consider whether to use Rug for everything, and use `secure_pow_mod` for RSA.
        // Not sure how different the security guarantees are...
        let signature = Integer::from_digits(signature.retrieve().as_words(), Order::Lsf);
        let index = key_share.index + 1;
        signature_shares.push(SignatureShare { index, signature });
        lagrange_indices.push(index as i64);
    }

    let total_shares: i64 = 5;
    let delta = shoup_delta(total_shares);

    let mut w = Integer::from(1);
    let n = Integer::from_digits(m.params().modulus().as_words(), Order::Lsf);

    for share in signature_shares {
        let sc = shoup_0_coefficient(share.index as i64, lagrange_indices.clone(), delta);

        let term = share.signature.pow_mod(&Integer::from(sc), &n).unwrap();
        w.mul_assign(&term);
        w.modulo_mut(&n);
    }

    let shoup_exp = Integer::from(delta);
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
