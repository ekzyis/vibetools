# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

Monorepo of small, self-contained "vibe-coded" tools, each built from scratch as
a learning exercise (e.g. a BIP-39 xpriv/xpub parser). One self-contained
directory per tool at the repo root; each documents its own build/test/run in a
README.

- **Implement, don't import.** The point is to learn by writing the code. Don't
  add a third-party *domain* library (e.g. `bip32`/`hdkey`); write the logic
  yourself. Default to from-scratch; when the depth is unclear (hand-write
  SHA-256/base58 vs. use the crypto stdlib), ask. Standard dev tooling (test
  runner, formatter, linter) is fine.
- Prefer Rust; use another language when it clearly fits a tool better.
- Favor readable, well-commented code over clever code.
- Default branch is `develop` (not `main`).
