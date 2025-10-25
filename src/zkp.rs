use std::collections::HashMap;
use std::fs;
use std::ops::Add;
use std::path::PathBuf;

use crypto_bigint::modular::BoxedMontyForm;
use crypto_bigint::{BoxedUint, RandomBits};
use sha2::{Digest, Sha256};

use crate::asn1::ShoupVerificationKey;
use crate::convert::asn1uint_to_boxed_monty;
use crate::{load_verify_shares, VerifyShare};

pub struct ProofContext {
    pub verification_key: BoxedMontyForm,
    verification_key_bytes: Box<[u8]>,
    pub message_witness: BoxedMontyForm,
    message_witness_bytes: Box<[u8]>,
    pub verification_shares: HashMap<u16, VerifyShare>,
    challenge_len_bits: u32,
    ephemeral_len_bits: u32,
}

pub struct Proof {
    pub key_commitment: BoxedMontyForm,
    pub msg_commitment: BoxedMontyForm,
    pub challenge: BoxedUint,
    pub response: BoxedUint,
}

pub fn build_proof_context(m: &BoxedMontyForm, dd: &BoxedUint) -> ProofContext {
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

pub fn build_proof(
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
