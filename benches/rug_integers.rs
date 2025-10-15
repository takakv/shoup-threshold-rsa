use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint,
};
use rand::rngs::OsRng;
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use rug::{integer::Order, Integer};

fn setup() -> (RsaPublicKey, BoxedMontyForm) {
    let mut rng = OsRng;

    let private_key = RsaPrivateKey::new(&mut rng, 3072).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let n_bytes = public_key.n().to_bytes_be();
    let n = BoxedUint::from_be_slice(&n_bytes, public_key.n().bits() as u32).unwrap();
    let params = BoxedMontyParams::new(n.to_odd().unwrap());

    let ui = BoxedUint::from_be_slice(&n_bytes, params.modulus().bits()).unwrap();
    let m = BoxedMontyForm::new(ui, params);

    let i1 = Integer::from_digits(black_box(m.params().modulus().as_words()), Order::Lsf);
    let i2 = Integer::from_digits(black_box(&public_key.n().to_bytes_be()), Order::Msf);
    let i3 = Integer::from_digits(black_box(&public_key.n().to_bytes_le()), Order::Lsf);
    assert_eq!(i1, i2);
    assert_eq!(i1, i3);

    (public_key, m)
}

fn rug_integers(c: &mut Criterion) {
    let (pk, boxed) = setup();

    c.bench_function("From Montgomery words", |b| {
        b.iter(|| {
            let i =
                Integer::from_digits(black_box(boxed.params().modulus().as_words()), Order::Lsf);
            black_box(i);
        })
    });

    c.bench_function("From RSA key bytes BE", |b| {
        b.iter(|| {
            let i = Integer::from_digits(black_box(&pk.n().to_bytes_be()), Order::Msf);
            black_box(i);
        })
    });

    c.bench_function("From RSA key bytes LE", |b| {
        b.iter(|| {
            let i = Integer::from_digits(black_box(&pk.n().to_bytes_le()), Order::Lsf);
            black_box(i);
        })
    });
}

criterion_group!(benches, rug_integers);
criterion_main!(benches);
