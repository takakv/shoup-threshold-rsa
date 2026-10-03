use std::path::PathBuf;

use itertools::Itertools;
use rand::SeedableRng;
use rand::rngs::ChaCha8Rng;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{Signature, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rug::Integer;
use rug::integer::Order;

use shoup_threshold_rsa::loaders::{load_key_share, load_pub_params};
use shoup_threshold_rsa::signature::{combine_shares, gen_signature_share, threshold_sign};
use shoup_threshold_rsa::{KeyShare, PublicParameters, SignatureShare, ThresholdParameters};

const MESSAGE: &[u8] = b"Practical Threshold Signatures";
const SEED: u64 = 0x12345678;
const PARAMS: ThresholdParameters = ThresholdParameters {
    threshold: 3,
    total_shares: 5,
};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/3-of-5")
        .join(path)
}

/// Mint and combine must use the same seed to compute the same PSS encoding.
fn rng() -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(SEED)
}

fn load_key_shares() -> Vec<KeyShare> {
    (0..PARAMS.total_shares)
        .map(|i| {
            let (key_share, _, _, _) =
                load_key_share(fixture(&format!("shares/share-{i}.der"))).unwrap();
            key_share
        })
        .collect()
}

/// All subsets of the 0-based share indices with at least `threshold` elements.
fn subsets() -> Vec<Vec<usize>> {
    let (threshold, total) = (PARAMS.threshold as usize, PARAMS.total_shares as usize);
    (threshold..=total)
        .flat_map(|size| (0..total).combinations(size))
        .collect()
}

fn mint(key_share: &KeyShare, pub_params: &PublicParameters) -> SignatureShare {
    let (signature, proof) = gen_signature_share(
        key_share,
        pub_params,
        MESSAGE,
        PARAMS.total_shares,
        None,
        &mut rng(),
    )
    .unwrap();
    SignatureShare {
        index: key_share.index,
        signature: Integer::from_digits(signature.as_words(), Order::Lsf),
        proof,
    }
}

#[test]
fn every_subset_signs() {
    let pub_params = load_pub_params(fixture("pub.pem")).unwrap();
    let verifying_key = VerifyingKey::<Sha256>::new(
        RsaPublicKey::read_public_key_pem_file(fixture("pub.pem")).unwrap(),
    );

    let is_valid_signature = |bytes: Vec<u8>| {
        let signature = Signature::try_from(bytes.as_slice()).unwrap();
        verifying_key.verify(MESSAGE, &signature).is_ok()
    };

    let key_shares = load_key_shares();
    let signature_shares: Vec<SignatureShare> = key_shares
        .iter()
        .map(|key_share| mint(key_share, &pub_params))
        .collect();

    let mut failures = Vec::new();
    for subset in subsets() {
        let shares: Vec<SignatureShare> = subset
            .iter()
            .map(|&i| SignatureShare {
                index: signature_shares[i].index,
                signature: signature_shares[i].signature.clone(),
                proof: None,
            })
            .collect();
        let combined =
            combine_shares(&shares, MESSAGE, &pub_params, &PARAMS, None, &mut rng()).unwrap();
        if !is_valid_signature(combined) {
            failures.push(format!("combine_shares {subset:?}"));
        }

        let keys: Vec<KeyShare> = subset
            .iter()
            .map(|&i| KeyShare {
                index: key_shares[i].index,
                d: key_shares[i].d.clone(),
            })
            .collect();
        let signed = threshold_sign(&keys, &pub_params, MESSAGE, &PARAMS, &mut rng()).unwrap();
        if !is_valid_signature(signed) {
            failures.push(format!("threshold_sign {subset:?}"));
        }
    }

    assert!(failures.is_empty(), "invalid signatures: {failures:#?}");
}
