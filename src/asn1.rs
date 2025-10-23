use rasn::prelude::OctetString;
use rasn::Decoder;
use rasn::{AsnType, Decode, Encode};

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

#[derive(Debug, Clone, AsnType, Encode, Decode)]
pub struct ShoupVerificationKey {
    pub vk: rasn::types::Integer,
}

#[derive(Debug, Clone, AsnType, Encode, Decode)]
pub struct ShoupVerifyShare {
    pub share_index: OctetString,
    pub public_share: rasn::types::Integer,
}
