use std::ops::Add;

use crypto_bigint::modular::BoxedMontyForm;
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::{BoxedUint, RandomBits, Word};
use rug::integer::Order;
use rug::Integer;
use sha2::{Digest, Sha256};

use crate::{PublicParameters, ShareProof};

fn challenge(
    vk: &BoxedMontyForm,
    x_bar: &BoxedMontyForm,
    v_i: &BoxedMontyForm,
    x_i_squared: &BoxedUint,
    v_prime: &BoxedMontyForm,
    x_prime: &BoxedMontyForm,
) -> BoxedUint {
    let h = Sha256::new()
        .chain_update(vk.retrieve().to_be_bytes())
        .chain_update(x_bar.retrieve().to_be_bytes())
        .chain_update(v_i.retrieve().to_be_bytes())
        .chain_update(x_i_squared.to_be_bytes())
        .chain_update(v_prime.retrieve().to_be_bytes())
        .chain_update(x_prime.retrieve().to_be_bytes())
        .finalize();
    BoxedUint::from_be_slice(&h, 256).unwrap()
}

pub fn prove(
    x: &BoxedMontyForm,
    pub_params: &PublicParameters,
    vk: &BoxedMontyForm,
    signature: &BoxedMontyForm,
    ss: &BoxedUint,
    delta: &Integer,
) -> ShareProof {
    let four_delta = BoxedUint::from_words((delta.clone() * 4u32).to_digits::<Word>(Order::Msf));
    let x_bar = x.pow(&four_delta);

    let r_bits = pub_params.monty_params.bits_precision() + 2 * 256;
    let r = BoxedUint::random_bits(&mut OsRng, r_bits);

    let v_prime = vk.pow(&r);
    let x_prime = x_bar.pow(&r);

    let v_i = vk.pow(&ss);
    let x_i_squared = signature.square().retrieve();

    let c = challenge(vk, &x_bar, &v_i, &x_i_squared, &v_prime, &x_prime);
    let z = ss.mul(&c).add(r);

    ShareProof {
        challenge: c,
        response: z,
    }
}

pub fn verify_proof(
    x: &BoxedMontyForm,
    v: &BoxedMontyForm,
    v_i: &BoxedMontyForm,
    signature: &BoxedMontyForm,
    proof: &ShareProof,
    delta: &Integer,
) -> bool {
    let four_delta = BoxedUint::from_words((delta.clone() * 4u32).to_digits::<Word>(Order::Msf));
    let x_bar = x.pow(&four_delta);

    let x_i_squared = signature.square().retrieve();

    let v_prime = v
        .pow(&proof.response)
        .mul(&v_i.pow(&proof.challenge).invert().unwrap());

    let x_prime = x_bar
        .pow(&proof.response)
        .mul(&signature.square().pow(&proof.challenge).invert().unwrap());

    let check = challenge(v, &x_bar, &v_i, &x_i_squared, &v_prime, &x_prime);

    check.eq(&proof.challenge)
}
