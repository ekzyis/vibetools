# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

Monorepo of small "vibe-coded" tools, each built from scratch as a learning
exercise (e.g. the `bip32` extended-key decoder). Each tool lives in its own root
folder and documents its own build/test/run in a README. Tools may depend on
each other (e.g. `bip32` reuses the `sha256` and `base58` tools).

- **Implement, don't import.** The point is to learn by writing the code. Don't
  add a third-party *domain* library (e.g. `bip32`/`hdkey`); write the logic
  yourself. Default to from-scratch; when the depth is unclear (hand-write
  SHA-256/base58 vs. use the crypto stdlib), ask. Standard dev tooling (test
  runner, formatter, linter) is fine.
- Prefer Rust; use another language when it clearly fits a tool better. Rust
  tools are crates in the root Cargo workspace (add new ones to `members`); a
  crate may expose modules, binary targets, or both. Reuse an existing crate
  (e.g. `sha256`, `base58`) instead of reimplementing a primitive.
- Favor readable, well-commented code over clever code.
- Default branch is `develop` (not `main`).
