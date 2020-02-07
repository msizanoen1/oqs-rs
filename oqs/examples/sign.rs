use oqs::{Error, Signature};

fn main() -> Result<(), Error> {
    let kenc = Signature::new("DILITHIUM_2")?;
    let (pk, sk) = kenc.keypair();
    println!("plen: {} slen: {}", pk.len(), sk.len());
    let sig = kenc.sign_to_vec(b"Hello", &sk)?;
    println!("sslen: {}", sig.len());
    kenc.verify(b"Hello", &sig, &pk)?;
    kenc.verify(b"Hellon't", &sig, &pk)?;
    Ok(())
}
