use der::asn1::{OctetStringRef, UintRef};
use der::Sequence;

#[derive(Clone, Sequence)]
pub struct ShamirSecretShare<'a> {
    pub share_index: OctetStringRef<'a>,
    pub secret_share: OctetStringRef<'a>,
}

#[derive(Clone, Sequence)]
pub struct ShoupKeyShare<'a> {
    pub n: UintRef<'a>,
    pub e: UintRef<'a>,
    pub d: UintRef<'a>,
}

#[derive(Clone, Sequence)]
pub struct ShoupVerificationKey<'a> {
    pub vk: UintRef<'a>,
}

#[derive(Clone, Sequence)]
pub struct ShoupVerifyShare<'a> {
    pub share_index: OctetStringRef<'a>,
    pub public_share: UintRef<'a>,
}
