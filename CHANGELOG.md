# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.8.0] - 2026-11-01

### Fixed

- Signatures, secret nonces, public nonces and aggregated nonces are now sliced by bytes (`byteslice`).
  Previously a binary string tagged as UTF-8 (e.g. read without binmode) could be split by characters and decoded incorrectly.
- Non-hex inputs are normalized to ASCII-8BIT, so signing a UTF-8 message containing non-ASCII characters no longer raises `Encoding::CompatibilityError`.
- `Schnorr.sign` now applies the same hex detection to the message as verification and MuSig2 do, so a hex-encoded message can be signed and verified consistently.
- `Schnorr.check_sig!` raises `Schnorr::InvalidSignatureError` instead of `ECDSA::Format::DecodeError` when the public key is not on the curve.
- `Schnorr::MuSig2.sort_pubkeys` sorts by raw bytes, so the order no longer depends on the letter case of hex input.
- `Schnorr::MuSig2.deterministic_sign` reduces the nonces modulo the group order and rejects zero, and `gen_nonce` stores the reduced nonces in the secret nonce, as specified in BIP-327.
- `Schnorr::MuSig2.aggregate` fails when the aggregate public key is the point at infinity, as specified in BIP-327.
- Fixed wrong or empty error messages in `gen_nonce` and `aggregate_nonce`.

### Added

- Length validation for `agg_nonce` (66 bytes), secret nonces (97 bytes), public nonces (66 bytes), secret keys (32 bytes) and `rand` (32 bytes) in the MuSig2 API, and range validation of `signer_index` in `SessionContext#valid_partial_sig?`. Invalid inputs raise `ArgumentError` instead of obscure errors.
- `gemspec` declares `required_ruby_version >= 3.2`.
- This CHANGELOG.

### Changed

- `Schnorr.sign` raises `ArgumentError` (instead of `RuntimeError`) for an invalid `private_key` or `aux_rand`.
- `SessionContext` keeps only SHA-256 digests of used secret nonces to detect reuse and no longer exposes `used_secnonces`.
- `SessionContext#sign` no longer performs two unnecessary scalar multiplications per partial signature.
- The challenge hash in `SessionContext` is computed once per session.
- Bumped `ecdsa_ext` to 0.6.0.

### Removed

- The dead `Integer#method_missing` / `Integer#mod_pow` shim for Ruby 2.4 and the unused `Integer#to_hex`.

### Notes

- Omitting `aux_rand` in `Schnorr.sign` still yields a deterministic signature (all-zero auxiliary data) for backward compatibility. Passing fresh randomness is recommended, as described in BIP-340.
