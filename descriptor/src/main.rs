//! descriptor-derive: derive the addresses a wallet descriptor describes.
//!
//! Reads the descriptor from the first non-flag CLI argument, or from stdin if
//! none is given.

use std::io::Read;

use descriptor::WalletDescriptor;

/// How many addresses to print when `-n` is not given.
const DEFAULT_COUNT: u32 = 20;

const USAGE: &str = "\
usage: descriptor-derive [-n COUNT] [--chain N] [--scripts] <descriptor>
       (or pipe the descriptor on stdin)

  -n COUNT   how many addresses to derive (default 20)
  --chain N  which chain of a multipath descriptor, e.g. <0;1>, to derive
             (default 0: the receiving chain)
  --scripts  also print each scriptPubKey in hex";

fn main() {
    let options = match parse_arguments(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    let text = match options.descriptor.or_else(read_stdin) {
        Some(text) if !text.trim().is_empty() => text,
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };

    let descriptor = match WalletDescriptor::parse_chain(&text, options.chain) {
        Ok(descriptor) => descriptor,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = print_addresses(&descriptor, options.count, options.scripts) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

struct Options {
    descriptor: Option<String>,
    count: u32,
    chain: usize,
    scripts: bool,
}

fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options {
        descriptor: None,
        count: DEFAULT_COUNT,
        chain: 0,
        scripts: false,
    };
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-n" | "--count" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} needs a count"))?;
                options.count = value
                    .parse()
                    .map_err(|_| format!("invalid count: {value:?}"))?;
                if options.count == 0 {
                    return Err("count must be at least 1".to_string());
                }
            }
            "--chain" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} needs a chain number"))?;
                options.chain = value
                    .parse()
                    .map_err(|_| format!("invalid chain: {value:?}"))?;
            }
            "--scripts" => options.scripts = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option: {other}"));
            }
            other => {
                if options.descriptor.is_some() {
                    return Err("more than one descriptor given".to_string());
                }
                options.descriptor = Some(other.to_string());
            }
        }
    }
    Ok(options)
}

fn read_stdin() -> Option<String> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer).ok()?;
    Some(buffer)
}

fn print_addresses(descriptor: &WalletDescriptor, count: u32, scripts: bool) -> Result<(), String> {
    let network = match descriptor.network() {
        bip32::Network::Mainnet => "mainnet",
        bip32::Network::Testnet => "testnet",
    };
    println!("descriptor {}", descriptor.canonical());
    if let Some(expanded) = descriptor.expanded_canonical() {
        println!(
            "chain      {} of {} (--chain selects another)",
            descriptor.chain, descriptor.chain_count
        );
        println!("expanded   {expanded}");
    }
    println!("output     {}", descriptor.output_kind());
    println!("network    {network}");

    // Without a wildcard the descriptor names a single script, not a list.
    let count = if descriptor.has_wildcard() { count } else { 1 };

    // The path column only makes sense when there is one key to show it for.
    let path = match descriptor.keys().as_slice() {
        [only] => Some(|index| only.path_at(index)),
        _ => None,
    };

    println!();
    let address_header = if scripts {
        "address / scriptPubKey"
    } else {
        "address"
    };
    match path {
        None => println!("{:>5}  {address_header}", "index"),
        Some(path) => {
            let width = (0..count).map(|i| path(i).len()).max().unwrap_or(4).max(4);
            println!("{:>5}  {:width$}  {address_header}", "index", "path");
            for index in 0..count {
                print_row(descriptor, index, Some((&path(index), width)), scripts)?;
            }
            return Ok(());
        }
    }
    for index in 0..count {
        print_row(descriptor, index, None, scripts)?;
    }
    Ok(())
}

/// One output row: the index, optionally the derivation path padded to `width`,
/// the address, and the scriptPubKey on a continuation line when asked for.
fn print_row(
    descriptor: &WalletDescriptor,
    index: u32,
    path: Option<(&str, usize)>,
    scripts: bool,
) -> Result<(), String> {
    let address = descriptor.address(index)?;
    match path {
        Some((path, width)) => println!("{index:>5}  {path:width$}  {address}"),
        None => println!("{index:>5}  {address}"),
    }
    if scripts {
        let script = descriptor.script_pubkey(index)?;
        let hex: String = script.iter().map(|b| format!("{b:02x}")).collect();
        match path {
            Some((_, width)) => println!("{:>5}  {:width$}  {hex}", "", ""),
            None => println!("{:>5}  {hex}", ""),
        }
    }
    Ok(())
}
