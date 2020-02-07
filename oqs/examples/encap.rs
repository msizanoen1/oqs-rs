use oqs::{Error, KeyEncap};

fn main() -> Result<(), Error> {
    let kenc = KeyEncap::new("SIKE-p751")?;
    println!("sslen: {} ctlen: {}", kenc.length_shared_secret(), kenc.length_ciphertext());
    let (pk, sk) = kenc.keypair();
    let (ct, ss) = kenc.encaps_to_vec(&pk)?;
    let ssd = kenc.decaps_to_vec(&ct, &sk)?;
    assert_eq!(ss, ssd);
    Ok(())
}
