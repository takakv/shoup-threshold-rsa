use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::BoxedUint;
use rug::Integer;

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

pub struct ShareProof {
    pub challenge: BoxedUint,
    pub response: BoxedUint,
}

pub struct SignatureShare {
    pub index: u16,
    pub signature: Integer,
    pub proof: Option<ShareProof>,
}

pub struct ThresholdParameters {
    pub threshold: u16,
    pub total_shares: u16,
}
