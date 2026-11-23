use confluence_core::ScopeKeypair;
use std::{env, error::Error, fs::OpenOptions, io::Write};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let path = args
        .next()
        .ok_or("usage: confluence-keygen <new-secret-file>")?;
    if args.next().is_some() {
        return Err("usage: confluence-keygen <new-secret-file>".into());
    }

    let identity = ScopeKeypair::generate();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let secret = Zeroizing::new(identity.secret_hex());
    writeln!(file, "{}", secret.as_str())?;
    println!("{}", identity.public_key());
    Ok(())
}
