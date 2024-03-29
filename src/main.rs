use bitcoin_hashes::hex::DisplayHex;
use bitcoin_hashes::{sha512, Hash};
use hex::FromHex;
use secp256k1::ecdh;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("example keys come from https://www.ietf.org/archive/id/draft-wahby-cfrg-hpke-kem-secp256k1-01.html#name-dhkemsecp256k1-hkdf-sha256-hk");
    let k256_privkeys: &[&[u8]] = &[
        &Vec::from_hex("30fbc0d41cd01885333211ff53b9ed29bcbdccc3ff13625a82db61a7bb8eae19")?,
        &Vec::from_hex("a795c287c132154a8b96dc81dc8b4e2f02bbbad78dab0567b59db1d1540751f6")?,
    ];

    println!(
        "privkey0: {}",
        k256_privkeys[0].to_hex_string(bitcoin_hashes::hex::Case::Upper)
    );
    println!(
        "privkey1: {}",
        k256_privkeys[1].to_hex_string(bitcoin_hashes::hex::Case::Upper)
    );

    let k256_pubkeys: &[&[u8]] = &[
        &Vec::from_hex(
            "04591775168f328a2adbcb887acd287d55a1025d7d2b15e1937278a5efd1d48b19c00cf07559320e6d278a71c9e58bae5d9ab041d7905c66291f4d08459c946e18"
        )?,
        &Vec::from_hex(
            "043ee7314407753d1ba296de29f07b2cd5505ca94b614f127e71f3c19fc7845daf49c9bb4bf4d00d3b5411c8eb86d59a2dcadc5a13115fa9fef44d1e0b7ef11cab"
        )?,
    ];

    println!(
        "pubkey0: {}",
        k256_pubkeys[0].to_hex_string(bitcoin_hashes::hex::Case::Upper)
    );
    println!(
        "pubkey1: {}",
        k256_pubkeys[1].to_hex_string(bitcoin_hashes::hex::Case::Upper)
    );

    let sk1 = secp256k1::SecretKey::from_slice(&k256_privkeys[0])?;
    let pk1 = secp256k1::PublicKey::from_slice(&k256_pubkeys[0])?;

    let sk2 = secp256k1::SecretKey::from_slice(&k256_privkeys[1])?;
    let pk2 = secp256k1::PublicKey::from_slice(&k256_pubkeys[1])?;

    println!("Calculating ecdh::shared_sectret_point(pubkey0, privkey1):");
    let point1 = ecdh::shared_secret_point(&pk1, &sk2);
    println!("{}", point1.to_hex_string(bitcoin_hashes::hex::Case::Upper));
    let secret1 = sha512::Hash::hash(&point1);
    println!("Calculating ecdh::shared_sectret_point(pubkey1, privkey0):");
    let point2 = ecdh::shared_secret_point(&pk2, &sk1);
    println!("{}", point2.to_hex_string(bitcoin_hashes::hex::Case::Upper));
    let secret2 = sha512::Hash::hash(&point2);
    assert_eq!(secret1, secret2);
    println!("shared_secrets match: {}", secret1);
    Ok(())
}
