use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint,
};
use rsa::BigUint;
use rug::integer::Order;

pub fn i2osp(i: rug::Integer, len: usize) -> Vec<u8> {
    let octets = &i.to_digits::<u8>(Order::Msf);
    if octets.len() > len {
        panic!("integer too large to encode in {} bytes", len);
    }

    let mut out = vec![0u8; len];
    out[len - octets.len()..].copy_from_slice(octets);
    out
}

pub fn monty_params_from_rsa_modulus(n: &BigUint) -> BoxedMontyParams {
    let n_bytes = n.to_bytes_be();
    let n = BoxedUint::from_be_slice(&n_bytes, n.bits() as u32)
        .expect("Failed to build BoxedUint from modulus");
    let n = n.to_odd().expect("RSA modulus is not odd");
    BoxedMontyParams::new(n)
}

pub fn os2ip_montgomery(octets: &[u8], mp: BoxedMontyParams) -> BoxedMontyForm {
    let ui = BoxedUint::from_be_slice(octets, mp.modulus().bits())
        .expect("Failed to build BoxedUint from octets");
    BoxedMontyForm::new(ui, mp)
}
