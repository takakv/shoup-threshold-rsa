use der::asn1::{OctetStringRef, UintRef};
use der::Sequence;

#[derive(Clone, Sequence)]
pub struct ShamirSecretShare<'a> {
    pub share_index: &'a OctetStringRef,
    pub share_count: &'a OctetStringRef,
    pub secret_share: &'a OctetStringRef,
    pub vk: Option<&'a OctetStringRef>,
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
    pub share_index: &'a OctetStringRef,
    pub public_share: UintRef<'a>,
}

#[derive(Clone, Sequence)]
pub struct SignatureShareDer<'a> {
    pub share_index: &'a OctetStringRef,
    pub signature: UintRef<'a>,
    pub proof: Option<&'a OctetStringRef>,
}

#[derive(Clone, Sequence)]
pub struct CorrectnessProofDer<'a> {
    pub c: UintRef<'a>,
    pub z: UintRef<'a>,
}
