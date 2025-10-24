use std::{
    collections::HashMap,
    fs::{self},
    ops::{Add, Mul, MulAssign},
    path::PathBuf,
};

use clap::Parser;
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams}, BitOps, BoxedUint, RandomBits,
    Word,
};
use rasn::types::IntegerType;
use rug::{integer::Order, Integer};
use sha2::{Digest, Sha256};

mod arithmetic;
mod asn1;
mod convert;
mod pss;

use arithmetic::{shoup_0_coefficient, shoup_delta};
use asn1::{ShamirSecretShare, ShoupKeyShare, ShoupVerificationKey, ShoupVerifyShare};
use convert::{asn1uint_to_boxed_monty, i2osp, os2ip_montgomery};
use pss::emsa_pss_encode;

pub struct KeyShare {
    pub index: u16,
    pub d: BoxedUint,
}

pub struct PublicParameters {
    pub n: Integer,
    pub e: Integer,
    pub byte_len: usize,
    pub monty_params: BoxedMontyParams,
}

pub struct VerifyShare {
    pub index: u16,
    pub vk: BoxedMontyForm,
}

pub struct SignatureShare {
    pub index: u16,
    pub signature: Integer,
}

struct ThresholdParameters {
    threshold: u16,
    total_shares: u16,
}

struct ProofContext {
    verification_key: BoxedMontyForm,
    verification_key_bytes: Box<[u8]>,
    message_witness: BoxedMontyForm,
    message_witness_bytes: Box<[u8]>,
    verification_shares: HashMap<u16, VerifyShare>,
    challenge_len_bits: u32,
    ephemeral_len_bits: u32,
}

struct Proof {
    key_commitment: BoxedMontyForm,
    msg_commitment: BoxedMontyForm,
    challenge: BoxedUint,
    response: BoxedUint,
}

fn build_proof_context(m: &BoxedMontyForm, dd: &BoxedUint) -> ProofContext {
    let vk_path = PathBuf::from("vk.der");
    let vk_shares_dir = PathBuf::from("vks");

    let vk = fs::read(&vk_path).expect("Failed to read verification key");
    let vk: ShoupVerificationKey =
        rasn::der::decode(&vk).expect("Failed to decode verification key");
    let verification_key = asn1uint_to_boxed_monty(vk.vk, m.params());

    let vk_shares = fs::read_dir(&vk_shares_dir).expect("Failed to list shares directory");

    let message_witness = m.pow(&dd.mul(&BoxedUint::from(2u8)));

    let challenge_len_bits = 8 * <Sha256>::output_size() as u32;

    ProofContext {
        verification_key_bytes: verification_key.retrieve().to_be_bytes(),
        verification_key,
        message_witness_bytes: message_witness.retrieve().to_be_bytes(),
        message_witness,
        verification_shares: load_verify_shares(vk_shares, m.params()),
        challenge_len_bits,
        ephemeral_len_bits: 2 * challenge_len_bits + m.bits_precision(),
    }
}

fn build_proof(
    ctx: &ProofContext,
    signature: &BoxedMontyForm,
    ss: &BoxedUint,
    vk: &BoxedUint,
) -> Proof {
    // Commitments
    let r = BoxedUint::random_bits(&mut crypto_bigint::rand_core::OsRng, ctx.ephemeral_len_bits);
    let v_prime = ctx.verification_key.pow(&r);
    let x_prime = ctx.message_witness.pow(&r);

    // Challenge
    let c = Sha256::new()
        .chain_update(&ctx.verification_key_bytes)
        .chain_update(&ctx.message_witness_bytes)
        .chain_update(vk.to_be_bytes())
        .chain_update(signature.square().retrieve().to_be_bytes())
        .chain_update(v_prime.retrieve().to_be_bytes())
        .chain_update(x_prime.retrieve().to_be_bytes())
        .finalize();
    let c = BoxedUint::from_be_slice(&c, ctx.challenge_len_bits).unwrap();

    // Response
    let z = ss.mul(&c).add(&r);

    Proof {
        key_commitment: v_prime,
        msg_commitment: x_prime,
        challenge: c,
        response: z,
    }
}

fn threshold_sign(
    key_shares: &[KeyShare],
    pub_params: &PublicParameters,
    msg: &[u8],
    params: &ThresholdParameters,
    provable: bool,
) -> Vec<u8> {
    assert!(params.threshold <= params.total_shares);

    if key_shares.len() < params.threshold as usize {
        panic!("not enough secret shares");
    }

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

fn load_key_shares<I>(entries: I) -> (Vec<KeyShare>, PublicParameters)
where
    I: IntoIterator<Item = std::io::Result<fs::DirEntry>>,
{
    let mut key_shares = Vec::new();
    let mut params: Option<PublicParameters> = None;

    for entry in entries {
        let entry = entry.expect("Invalid directory entry");
        let path = entry.path();

        if !path.is_file() {
            continue;
        };

        let data = fs::read(&path).expect("Failed to read share file");
        let shamir_share: ShamirSecretShare =
            rasn::der::decode(&data).expect("Failed to decode Shamir secret share");

        let bytes = &shamir_share.share_index;
        let mut buf = [0u8; 2];
        let start = 2 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        let rsa_share: ShoupKeyShare =
            rasn::der::decode(&shamir_share.secret_share).expect("Failed to decode RSA share");

        let (d_bytes, d_len) = rsa_share.d.to_unsigned_bytes_be();
        let d_boxed = BoxedUint::from_be_slice(d_bytes.as_ref(), (d_len * 8) as u32)
            .expect("Failed to build BoxedUint");
        key_shares.push(KeyShare { index, d: d_boxed });

        if params.is_none() {
            let (n_bytes, _) = rsa_share.n.to_unsigned_bytes_be();
            let n = Integer::from_digits(n_bytes.as_ref(), Order::Msf);

            let (e_bytes, _) = rsa_share.e.to_unsigned_bytes_be();
            let e = Integer::from_digits(e_bytes.as_ref(), Order::Lsf);

            let n_words = n.to_digits::<Word>(Order::Lsf);
            let n_boxed = BoxedUint::from_words(n_words);
            let n_odd = n_boxed.to_odd().expect("RSA modulus is not odd");

            params = Some(PublicParameters {
                n,
                e,
                byte_len: n_odd.bytes_precision(),
                monty_params: BoxedMontyParams::new(n_odd),
            });
        }
    }

    let params = params.expect("Could not parse RSA public parameters");
    (key_shares, params)
}

fn load_verify_shares<I>(entries: I, mp: &BoxedMontyParams) -> HashMap<u16, VerifyShare>
where
    I: IntoIterator<Item = std::io::Result<fs::DirEntry>>,
{
    let mut verify_shares = HashMap::new();
    for entry in entries {
        let entry = entry.expect("Invalid directory entry");
        let path = entry.path();

        if !path.is_file() {
            continue;
        };

        let data = fs::read(&path).expect("Failed to read share file");
        let verify_share: ShoupVerifyShare =
            rasn::der::decode(&data).expect("Failed to decode verification share");

        let bytes = &verify_share.share_index;
        let mut buf = [0u8; 2];
        let start = 2 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        let index = u16::from_be_bytes(buf) + 1;

        verify_shares.insert(
            index,
            VerifyShare {
                index,
                vk: asn1uint_to_boxed_monty(verify_share.public_share, mp),
            },
        );
    }

    verify_shares
}

#[derive(Parser, Debug)]
struct Args {
    /// File to read the data from
    #[arg(long = "in", short)]
    infile: PathBuf,

    /// Filename to output the signature to
    #[arg(long = "out", short)]
    outfile: PathBuf,

    /// Directory containing the private key shares
    shares: PathBuf,

    /// Minimum number of shares required for signing
    #[arg(short, long)]
    threshold: u16,

    /// Number of total shareholders
    #[arg(short = 'T', long)]
    total: u16,
}

fn main() {
    let args = Args::parse();

    let parameters = ThresholdParameters {
        threshold: args.threshold,
        total_shares: args.total,
    };

    let provable = false;

    let msg = fs::read(&args.infile).expect("Failed to read message file");

    let entries = fs::read_dir(&args.shares).expect("Failed to list shares directory");
    let (key_shares, pub_params) = load_key_shares(entries);

    let signature = threshold_sign(&key_shares, &pub_params, &msg, &parameters, provable);
    fs::write(&args.outfile, &signature).expect("Failed to write signature to file");
}
