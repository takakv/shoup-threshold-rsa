use std::fs;
use std::fs::File;
use std::io::Write;
use std::ops::{AddAssign, Sub};
use std::path::Path;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::{BoxedUint, RandomMod};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use rasn::types::IntegerType;
use rasn::Codec;
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::EncodePublicKey;
use rsa::{BigUint, RsaPublicKey};

use crate::asn1::{ShamirSecretShare, ShoupKeyShare};
use crate::ThresholdParameters;

const PUB_EXP: u32 = u16::MAX as u32 + 2;

fn gen_safe_prime(bits: i32) -> Result<BigNum, ErrorStack> {
    let mut bn = BigNum::new()?;
    bn.generate_prime(bits, true, None, None)?;
    Ok(bn)
}

pub fn generate(
    bits: u32,
    params: &ThresholdParameters,
    pub_path: impl AsRef<Path>,
    shares_dir: impl AsRef<Path>,
) {
    let p = gen_safe_prime(bits as i32).unwrap();
    let q = gen_safe_prime(bits as i32).unwrap();

    let p = BoxedUint::from_be_slice(&p.to_vec(), bits).unwrap();
    let q = BoxedUint::from_be_slice(&q.to_vec(), bits).unwrap();

    // let p = BoxedUint::from_str_radix_vartime(
    //     "26721790369041029130868520763295151254217321491087464401697308359428124568208418796785374594386483708769500392956109451369301964202268719910199513514635514892411322231917573962006404206468500563453468144452383175758744984316887938512985683705353295737253011586022713748208365982283339040315723992733221272897387781928834985765343287777982894909818001847927312694363468520293022758689051398560934996468923297466425872806263557843750264768675232356878249924473059819052587468596107560268401592637155883539412546801642358620515787130219870781673848055336564847264702211278359971042396542911329690277899759771918085371267",
    //     10,
    // ).unwrap();
    // let q = BoxedUint::from_str_radix_vartime(
    //     "26178275421079800129280651342446662497530433875413992515120574920971083157456612595031324883045802192806461544118942558923086234254607862462974313136223147383089944834039945685458133425275094317250040487697018190686643342565024928526945860212920517283531185867398947590278548226291800534173484093880985975617381513386490753993338492848940975946401986077692149429720127419145951937328371351280512390744306069796821289312800253193352176072490218176612840619292556589555403413179993760037717833976465824335447073713767255623627030840825232724512105308403906866675153321735219092839100237223879194477515528161890842289107",
    //     10,
    // ).unwrap();

    assert_ne!(&p, &q);

    let pp = p.clone().sub(BoxedUint::one()).shr(1);
    let qq = q.clone().sub(BoxedUint::one()).shr(1);

    let n = p.mul(&q);
    let m = pp.mul(&qq).to_odd().unwrap();

    let e = BoxedUint::from(PUB_EXP).widen(m.bits_precision());
    let d = e.inv_odd_mod(&m).unwrap();

    let e = BigUint::from(PUB_EXP);
    let n = BigUint::from_slice_native(n.as_words());
    let pubkey = RsaPublicKey::new(n.clone(), e).unwrap();

    pubkey
        .write_public_key_pem_file(pub_path, LineEnding::LF)
        .expect("Failed to write public key");

    let e = rasn::types::Integer::from(PUB_EXP);
    let n = rasn::types::Integer::try_from_unsigned_bytes(&n.to_bytes_be(), Codec::Der).unwrap();

    let mp = BoxedMontyParams::new(m.clone());

    let mut coefficients = Vec::with_capacity(params.threshold as usize);
    let mut indices = Vec::with_capacity(coefficients.len());

    coefficients.push(BoxedMontyForm::new(d, mp.clone()));
    indices.push(BoxedUint::zero().widen(m.bits_precision()));

    for i in 1..coefficients.len() as u32 {
        let tmp = BoxedUint::random_mod(&mut OsRng, m.as_nz_ref());
        coefficients.push(BoxedMontyForm::new(tmp, mp.clone()));
        indices.push(BoxedUint::from(i).widen(m.bits_precision()));
    }

    let shares_dir = shares_dir.as_ref();
    fs::create_dir_all(&shares_dir).expect("Failed to create shares dir");

    let zero = BoxedMontyForm::zero(mp.clone());
    for i in 1..1 + params.total_shares {
        let mi = BoxedUint::from(i).widen(m.bits_precision());
        let mi = BoxedMontyForm::new(mi, mp.clone());

        let mut sum = zero.clone();
        for j in 0..coefficients.len() {
            sum.add_assign(&mi.pow(&indices[j]).mul(&coefficients[j]));
        }

        let d = sum.retrieve().to_be_bytes();
        let d = rasn::types::Integer::try_from_unsigned_bytes(&d, Codec::Der).unwrap();

        let shoup = ShoupKeyShare {
            n: n.clone(),
            e: e.clone(),
            d,
        };

        let shamir = ShamirSecretShare {
            share_index: (i - 1).to_be_bytes().into(),
            secret_share: rasn::der::encode(&shoup).unwrap().into(),
        };

        let tmp = rasn::der::encode(&shamir).unwrap();

        let filename = shares_dir.join(format!("share-{}.bin", i - 1));
        let mut file = File::create(&filename).unwrap();
        file.write_all(&tmp).expect("Failed to write share");
    }
}
