use rand::{rand_core::OsRng, TryRngCore};
use rsa::signature::digest::{Digest, FixedOutputReset};

fn mgf1_xor_mask<D>(out: &mut [u8], seed: &[u8])
where
    D: Digest + FixedOutputReset,
{
    let h_len = <D as Digest>::output_size();

    // RFC 8017 requires that maskLen <= 2^32 hLen.
    // Indeed, otherwise the 4-byte counter will overflow.
    assert!(out.len() as u64 <= (h_len as u64) << 32);

    let mut counter = 0u32;

    let mut i = 0;
    while i < out.len() {
        let digest = D::new()
            .chain_update(seed)
            .chain_update(counter.to_be_bytes())
            .finalize();

        let mut j = 0;
        while j < h_len && i < out.len() {
            out[i] ^= digest[j];
            i += 1;
            j += 1;
        }
        counter += 1;
    }
}

pub fn emsa_pss_encode<D>(message: &[u8], em_bits: usize) -> Vec<u8>
where
    D: Digest + FixedOutputReset,
{
    let h_len = <D as Digest>::output_size();
    let s_len = h_len; // Use the same hash function for the message and MGF1.
    let em_len = (em_bits + 7) / 8;

    // In the end, EM = maskedDB || H || 0xbc.
    let mut em = vec![0u8; em_len];
    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..h_len];

    // 2. Let mHash = Hash(M), an octet string of length hLen.
    let m_hash = D::digest(message);

    // 3. If emLen < hLen + sLen + 2, output "encoding error" and stop.
    if em_len < h_len + s_len + 2 {
        panic!("encoding error");
    }

    // 4. Generate a random octet string salt of length sLen; if sLen =
    //    0, then salt is the empty string.
    let mut salt = vec![0u8; s_len];
    OsRng
        .try_fill_bytes(&mut salt)
        .expect("Could not generate PSS salt");

    // 5. Let
    //       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    //    M' is an octet string of length 8 + hLen + sLen with eight
    //    initial zero octets.
    //
    // 6. Let H = Hash(M'), an octet string of length hLen.
    let hasher = D::new()
        .chain_update([0u8; 8])
        .chain_update(m_hash)
        .chain_update(&salt);
    h.copy_from_slice(&hasher.finalize());

    // 7. Generate an octet string PS consisting of emLen - sLen - hLen
    //    - 2 zero octets.  The length of PS may be 0.
    //
    // 8. Let DB = PS || 0x01 || salt; DB is an octet string of length
    //    emLen - hLen - 1.
    let ps_len_plus_one = em_len - s_len - h_len - 1;
    db[ps_len_plus_one - 1] = 0x01;
    db[ps_len_plus_one..].copy_from_slice(&salt);

    // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
    // 10. Let maskedDB = DB \xor dbMask.
    mgf1_xor_mask::<D>(db, &h);

    // 11. Set the leftmost 8emLen - emBits bits of the leftmost octet
    //     in maskedDB to zero.
    db[0] &= 0xFF >> (8 * em_len - em_bits);

    // 12. Let EM = maskedDB || H || 0xbc.
    em[em_len - 1] = 0xBC;

    // 13. Output EM.
    em
}
