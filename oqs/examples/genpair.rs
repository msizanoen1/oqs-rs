use oqs::KeyEncap;
use std::env;
use std::fs::File;
use std::io::{self, Write};

fn main() -> io::Result<()> {
    let kenc = KeyEncap::new("SIKE-p751").unwrap();
    let (pk, sk) = kenc.keypair();
    let mut args = env::args().skip(1);
    let mut pf = File::create(args.next().unwrap())?;
    let mut sf = File::create(args.next().unwrap())?;
    pf.write_all(&pk)?;
    sf.write_all(&sk)?;
    Ok(())
}
