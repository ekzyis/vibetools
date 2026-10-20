# descriptor

Output script descriptors: parse one and derive the addresses it describes.
Hand-written from scratch, on top of the `sha256`, `sha512`, `ripemd160`,
`base58`, `bech32`, `secp256k1` and `bip32` vibetools.

A descriptor is a small expression that says exactly which scriptPubKeys a
wallet owns. Each function describes one layer of the script, the key
expressions inside describe the keys, and a `*` wildcard turns the whole thing
into an endless list of scripts — one per address index:

```text
  wpkh([d34db33f/84h/0h/0h]zpub6rFR7...GutZYs/0/*)#86wvxfz6
  └┬─┘ └──── origin ─────┘ └── key ──────────┘ │  └ checksum
   │                                           └ wildcard
   └ the script layer: pay to a witness public key hash
```

## Usage

```sh
cargo run -p descriptor --bin descriptor-derive -- '<descriptor>'
echo '<descriptor>' | cargo run -p descriptor --bin descriptor-derive
```

```text
  -n COUNT   how many addresses to derive (default 20)
  --chain N  which chain of a multipath descriptor to derive (default 0)
  --scripts  also print each scriptPubKey in hex
```

Example:

```
$ descriptor-derive -n 3 'wpkh([73c5da0a/84h/0h/0h]zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs/0/*)'
descriptor wpkh([73c5da0a/84h/0h/0h]zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs/0/*)#86wvxfz6
output     p2wpkh
network    mainnet

index  path           address
    0  84h/0h/0h/0/0  bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
    1  84h/0h/0h/0/1  bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g
    2  84h/0h/0h/0/2  bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z
```

The checksum is printed back even when the input had none, so it can be copied
into a wallet. A descriptor with no wildcard describes a single script, and
exactly one address is printed.

### Multipath descriptors

A path element written as a tuple, `/<0;1>/`, is BIP-389 notation for several
descriptors in one string — wallets use it to keep the receiving and change
descriptors together, since they differ in exactly that one step. `--chain`
picks which one to derive (0 is the receiving chain), and the single-path
descriptor it expands into is printed with its own checksum:

```
$ descriptor-derive --chain 1 'wsh(sortedmulti(2,[b1556a94/48h/0h/0h/2h]xpub6Ebjo.../<0;1>/*,[f1f4b909/48h/0h/0h/2h]xpub6FPxx.../<0;1>/*))#znl7g27s'
descriptor wsh(sortedmulti(2,[b1556a94/48h/0h/0h/2h]xpub6Ebjo.../<0;1>/*,...))#znl7g27s
chain      1 of 2 (--chain selects another)
expanded   wsh(sortedmulti(2,[b1556a94/48h/0h/0h/2h]xpub6Ebjo.../1/*,...))#mfgt9xzs
output     p2wsh
network    mainnet

index  address
    0  bc1qtqflykrmr7tagcs6ecrcuhptzs6nyc3re8x7xpajj3clss7dqweswamlg7
  ...
```

Tuples may hold more than two values, and a descriptor with several of them
steps through them in lockstep, so they must all be the same length. Only one
tuple is allowed per key expression, and none inside a key origin.

Exit codes: `0` success, `1` parse/derivation error, `2` bad usage or no input.

## What it supports

| Descriptor | Output |
| --- | --- |
| `pkh(KEY)` | P2PKH, `1...` |
| `wpkh(KEY)` | P2WPKH, `bc1q...` |
| `sh(wpkh(KEY))` | P2SH-wrapped P2WPKH, `3...` |
| `wsh(SCRIPT)` | P2WSH, `bc1q...` (32-byte program) |
| `sh(wsh(SCRIPT))` | P2SH-wrapped P2WSH, `3...` |
| `sh(SCRIPT)` | P2SH, `3...` |
| `tr(KEY)` | P2TR (key path only), `bc1p...` |
| `pk(KEY)`, `multi(k,KEY...)`, `sortedmulti(k,KEY...)` | the script, which has no address |

`multi()` and `sortedmulti()` go inside `sh()` or `wsh()` to get an address;
`sortedmulti()` puts the *derived* keys in lexicographic order, so every signer
builds the same script regardless of the order the keys are written in.

Multipath tuples (`/<0;1>/`, BIP-389) are supported; see above.

Keys are extended keys: `xpub`/`xprv`, testnet `tpub`/`tprv`, and the SLIP-132
prefixes wallets export (`ypub`, `zpub`, `upub`, `vpub`, `Ypub`, `Zpub`, …).
Each may carry key origin info (`[fingerprint/path]`) and its own derivation
path, ending in `*` or `*h`. Hardened path steps need a private key, so
`xpub.../0h/*` parses but cannot be derived — the error says so.

## Test

```sh
cargo test -p descriptor
```

Tested against the specification test vectors:

* BIP-380 — the checksum and key expression cases (valid and invalid).
* BIP-382, BIP-383 — the `wpkh()`, `sh(wpkh())`, `multi()`, `sortedmulti()` and
  `wsh(multi())` scriptPubKeys, for every vector written with extended keys,
  plus the invalid nesting and threshold cases.
* BIP-84, BIP-49, BIP-86 — the reference accounts' first receive and change
  addresses, i.e. the whole path from an account xpub to a P2WPKH, nested
  segwit and taproot address.
* BIP-341/BIP-86 — the taproot internal-key-to-output-key tweak.
* BIP-389 — every multipath descriptor and the descriptors it expands into,
  plus the invalid cases (two tuples in one key expression, a tuple in an
  origin, mismatched lengths, malformed tuples).

## Scope

Deriving addresses from a watch-only or signing descriptor; it does not spend,
sign or build transactions. Not supported, and reported as such rather than
guessed at:

* miniscript inside `wsh()` (`and_v`, `or_b`, `thresh`, `older`, …) and
  `multi_a()`;
* taproot script trees — `tr(KEY,TREE)`, only `tr(KEY)`;
* `combo()`, `raw()`, `addr()` and `rawtr()`;
* bare hex public keys and WIF private keys as key expressions — keys are
  extended keys.
