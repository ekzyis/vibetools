//! bip32-decode: decode a BIP-32 extended key (xpub/xprv) into its components.
//!
//! Reads the key from the first CLI argument, or from stdin if none is given.

use std::io::Read;

use bip32::ExtendedKey;

fn main() {
    let key = match read_input() {
        Some(k) if !k.trim().is_empty() => k,
        _ => {
            eprintln!("usage: bip32-decode <xpub|xprv>   (or pipe the key on stdin)");
            std::process::exit(2);
        }
    };

    match ExtendedKey::parse(&key) {
        Ok(k) => print_key(&k),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Return the key from argv[1], or the whole of stdin if no argument is given.
fn read_input() -> Option<String> {
    if let Some(arg) = std::env::args().nth(1) {
        return Some(arg);
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).ok()?;
    Some(buf)
}

fn print_key(k: &ExtendedKey) {
    // The literal BIP-32 serialized fields, in order.
    println!("version            {:#010x}", k.version);
    println!("depth              {}", k.depth);
    println!("parent fingerprint {}", hex(&k.parent_fingerprint));
    println!("child number       {:#010x}", k.child_number);
    println!("chain code         {}", hex(&k.chain_code));
    println!("key data           {}", hex(&k.key_data));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
