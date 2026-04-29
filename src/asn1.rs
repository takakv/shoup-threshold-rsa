use der::asn1::{OctetStringRef, UintRef};
use der::Sequence;

#[derive(Clone, Sequence)]
pub struct ShamirSecretShare<'a> {
    pub share_index: OctetStringRef<'a>,
    pub share_count: OctetStringRef<'a>,
    pub secret_share: OctetStringRef<'a>,
    pub vk: Option<OctetStringRef<'a>>,
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

#[derive(Clone, Sequence)]
pub struct SignatureShareDer<'a> {
    pub share_index: OctetStringRef<'a>,
    pub signature: UintRef<'a>,
    pub proof: Option<OctetStringRef<'a>>,
}

#[derive(Clone, Sequence)]
pub struct CorrectnessProofDer<'a> {
    pub c: UintRef<'a>,
    pub z: UintRef<'a>,
}
