//! Host-only helpers for producing legacy test coins and migration
//! authorizations. Nothing here is consensus.

use alloc::vec::Vec;

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;

use crate::{hash160, sha256, MigrationAuth};

pub fn secret_from_bytes(b: &[u8; 32]) -> Option<k256::SecretKey> {
    k256::SecretKey::from_slice(b).ok()
}

pub fn compressed_pubkey(sk: &k256::SecretKey) -> Vec<u8> {
    sk.public_key().to_encoded_point(true).as_bytes().to_vec()
}

pub fn uncompressed_pubkey(sk: &k256::SecretKey) -> Vec<u8> {
    sk.public_key().to_encoded_point(false).as_bytes().to_vec()
}

pub fn ecdsa_sign(sk: &k256::SecretKey, msg: &[u8; 32]) -> [u8; 64] {
    let signing = k256::ecdsa::SigningKey::from(sk);
    let sig: k256::ecdsa::Signature = signing.sign_prehash(msg).expect("sign");
    let sig = sig.normalize_s().unwrap_or(sig);
    let b: [u8; 64] = sig.to_bytes().into();
    b
}

/// BIP340 x-only public key of `sk` (no tweak).
fn schnorr_key(sk: &k256::SecretKey) -> k256::schnorr::SigningKey {
    k256::schnorr::SigningKey::from_bytes(&sk.to_bytes()).expect("valid secret")
}

pub fn xonly_pubkey(sk: &k256::SecretKey) -> [u8; 32] {
    let signing = schnorr_key(sk);
    signing.verifying_key().to_bytes().into()
}

/// BIP341 key-path tweak with no script tree: returns the tweaked secret.
pub fn taproot_tweak(sk: &k256::SecretKey) -> k256::SecretKey {
    use k256::elliptic_curve::ops::Reduce;
    let signing = schnorr_key(sk);
    // k256's schnorr SigningKey already negates to even-y internally; take its scalar.
    let d = signing.as_nonzero_scalar();
    let internal_x: [u8; 32] = signing.verifying_key().to_bytes().into();
    let tag = sha256(b"TapTweak");
    let t_bytes = sha256(&[&tag[..], &tag[..], &internal_x[..]].concat());
    let t = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(&t_bytes.into());
    let d2 = **d + t;
    let repr = d2.to_repr();
    k256::SecretKey::from_slice(&repr).expect("nonzero")
}

pub fn schnorr_sign(sk: &k256::SecretKey, msg: &[u8; 32]) -> [u8; 64] {
    let signing = schnorr_key(sk);
    let sig: k256::schnorr::Signature = signing.sign_prehash_with_aux_rand(msg, &[0u8; 32]).expect("sign");
    sig.to_bytes()
}

pub fn script_p2pkh(pubkey: &[u8]) -> Vec<u8> {
    let mut s = alloc::vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&hash160(pubkey));
    s.extend_from_slice(&[0x88, 0xac]);
    s
}
pub fn script_p2wpkh(pubkey: &[u8]) -> Vec<u8> {
    let mut s = alloc::vec![0x00, 0x14];
    s.extend_from_slice(&hash160(pubkey));
    s
}
pub fn script_p2sh_p2wpkh(pubkey: &[u8]) -> Vec<u8> {
    let redeem = script_p2wpkh(pubkey);
    script_p2sh_of(&redeem)
}
pub fn script_p2sh_of(redeem: &[u8]) -> Vec<u8> {
    let mut s = alloc::vec![0xa9, 0x14];
    s.extend_from_slice(&hash160(redeem));
    s.push(0x87);
    s
}
pub fn script_p2wsh_of(witness_script: &[u8]) -> Vec<u8> {
    let mut s = alloc::vec![0x00, 0x20];
    s.extend_from_slice(&sha256(witness_script));
    s
}
pub fn script_p2pk(pubkey: &[u8]) -> Vec<u8> {
    let mut s = alloc::vec![pubkey.len() as u8];
    s.extend_from_slice(pubkey);
    s.push(0xac);
    s
}
pub fn script_p2tr(xonly_output_key: &[u8; 32]) -> Vec<u8> {
    let mut s = alloc::vec![0x51, 0x20];
    s.extend_from_slice(xonly_output_key);
    s
}
pub fn script_multisig(k: usize, pubkeys: &[Vec<u8>]) -> Vec<u8> {
    let mut s = alloc::vec![0x50 + k as u8];
    for pk in pubkeys {
        s.push(pk.len() as u8);
        s.extend_from_slice(pk);
    }
    s.push(0x50 + pubkeys.len() as u8);
    s.push(0xae);
    s
}

/// Convenience: build the authorization for the common single-key templates.
pub fn auth_keyhash(sk: &k256::SecretKey, msg: &[u8; 32], compressed: bool) -> MigrationAuth {
    let pubkey = if compressed { compressed_pubkey(sk) } else { uncompressed_pubkey(sk) };
    MigrationAuth::KeyHash { pubkey, sig: ecdsa_sign(sk, msg) }
}
pub fn auth_p2pk(sk: &k256::SecretKey, msg: &[u8; 32]) -> MigrationAuth {
    MigrationAuth::PubKey { sig: ecdsa_sign(sk, msg) }
}
/// `sk` is the *internal* key; the tweak is applied here.
pub fn auth_taproot(sk: &k256::SecretKey, msg: &[u8; 32]) -> MigrationAuth {
    MigrationAuth::Taproot { sig: schnorr_sign(&taproot_tweak(sk), msg) }
}
pub fn auth_multisig(script: &[u8], sks: &[&k256::SecretKey], msg: &[u8; 32]) -> MigrationAuth {
    MigrationAuth::Multisig { script: script.to_vec(), sigs: sks.iter().map(|sk| ecdsa_sign(sk, msg)).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_migration;

    fn sk(i: u8) -> k256::SecretKey {
        secret_from_bytes(&[i; 32]).unwrap()
    }

    #[test]
    fn all_templates_verify() {
        let m = sha256(b"msg");
        let k1 = sk(1);
        let k2 = sk(2);
        let k3 = sk(3);
        let pk1 = compressed_pubkey(&k1);

        assert!(verify_migration(&script_p2pkh(&pk1), &m, &auth_keyhash(&k1, &m, true)));
        assert!(verify_migration(&script_p2pkh(&uncompressed_pubkey(&k1)), &m, &auth_keyhash(&k1, &m, false)));
        assert!(!verify_migration(&script_p2pkh(&pk1), &m, &auth_keyhash(&k2, &m, true)));
        assert!(verify_migration(&script_p2wpkh(&pk1), &m, &auth_keyhash(&k1, &m, true)));
        assert!(verify_migration(&script_p2sh_p2wpkh(&pk1), &m, &auth_keyhash(&k1, &m, true)));
        assert!(verify_migration(&script_p2pk(&pk1), &m, &auth_p2pk(&k1, &m)));
        assert!(!verify_migration(&script_p2pk(&pk1), &m, &auth_p2pk(&k2, &m)));

        let output_key = xonly_pubkey(&taproot_tweak(&k1));
        assert!(verify_migration(&script_p2tr(&output_key), &m, &auth_taproot(&k1, &m)));
        assert!(!verify_migration(&script_p2tr(&output_key), &m, &auth_taproot(&k2, &m)));

        let ms = script_multisig(2, &[compressed_pubkey(&k1), compressed_pubkey(&k2), compressed_pubkey(&k3)]);
        assert!(verify_migration(&script_p2wsh_of(&ms), &m, &auth_multisig(&ms, &[&k1, &k3], &m)));
        assert!(verify_migration(&script_p2sh_of(&ms), &m, &auth_multisig(&ms, &[&k2, &k3], &m)));
        // wrong order fails (CHECKMULTISIG semantics)
        assert!(!verify_migration(&script_p2wsh_of(&ms), &m, &auth_multisig(&ms, &[&k3, &k1], &m)));
        assert!(!verify_migration(&script_p2wsh_of(&ms), &m, &auth_multisig(&ms, &[&k1], &m)));
    }
}
