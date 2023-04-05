# bip-schnorrrb [![Build Status](https://github.com/chaintope/bip-schnorrrb/actions/workflows/ruby.yml/badge.svg?branch=master)](https://travis-ci.org/chaintope/bip-schnorrrb) [![Gem Version](https://badge.fury.io/rb/bip-schnorr.svg)](https://badge.fury.io/rb/bip-schnorr) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE) 

This is a Ruby implementation of the Schnorr signature scheme over the elliptic curve. 
This implementation relies on the [ecdsa gem](https://github.com/DavidEGrayson/ruby_ecdsa) for operate elliptic curves.

The code is based upon the [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'bip-schnorr', require: 'schnorr'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install bip-schnorr

## Usage

### Signing

```ruby
require 'schnorr'

private_key = ['B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF'].pack("H*")

message = ['5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C'].pack('H*')

# create signature
signature = Schnorr.sign(message, private_key)
# if use auxiliary random data, specify it to the 3rd arguments.
aux_rand = SecureRandom.bytes(32) # aux_rand must be a 32-byte binary.
signature = Schnorr.sign(message, private_key, aux_rand)

# signature r value
signature.r 

# signature s value
signature.s 

# convert signature to binary

signature.encode

```

### Verification

```ruby
require 'schnorr'

# public key does not start with 02 or 03.
public_key = ['DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'].pack('H*')

signature = ['6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'].pack('H*')

message = ['243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89'].pack('H*')

# verify signature.(result is true or false)
result = Schnorr.valid_sig?(message, public_key, signature) 

# signature convert to Signature object
sig = Schnorr::Signature.decode(signature) 
```

### MuSig2*

This library support MuSig2* as defined [BIP-327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

```ruby
require 'schnorr'

sk1 = 1 + SecureRandom.random_number(Schnorr::GROUP.order - 1)
pk1 = (Schnorr::GROUP.generator.to_jacobian * sk1).to_affine.encode

sk2 = 1 + SecureRandom.random_number(Schnorr::GROUP.order - 1)
pk2 = (Schnorr::GROUP.generator.to_jacobian * sk2).to_affine.encode

pubkeys = [pk1, pk2]

# Key aggregation.
agg_ctx = Schnorr::MuSig2.aggregate(pubkeys)
# if you have tweak value.
agg_ctx = Schnorr::MuSig2.aggregate_with_tweaks(pubkeys, tweaks, modes)

## Aggregated pubkey is
### Return point:
agg_ctx.q
### Return x-only pubkey string
agg_ctx.x_only_pubkey

msg = SecureRandom.bytes(32)

# Generate secret nonce and public nonce.
sec_nonce1, pub_nonce1 = Schnorr::MuSig2.gen_nonce(
        pk: pk1,
        sk: sk1,  # optional
        agg_pubkey: agg_ctx.x_only_pubkey,  # optional
        msg: msg, # optional
        extra_in: SecureRandom.bytes(4),  # optional
        rand: SecureRandom.bytes(32)  # optional
)

## for stateless signer.
agg_other_nonce = described_class.aggregate_nonce([pub_nonce1])
pub_nonce2, sig2 = described_class.deterministic_sign(
        sk2, agg_other_nonce, pubkeys, msg, 
        tweaks: tweaks, # optional
        modes: modes, # optional
        rand: SecureRandom.bytes(32)  # optional
)

# Nonce aggregation
agg_nonce = Schnorr::MuSig2.aggregate_nonce([pub_nonce1, pub_nonce2])

# Generate partial signature.
session_ctx = Schnorr::MuSig2::SessionContext.new(
        agg_nonce, pubkeys, msg, 
        tweaks, # optional
        modes # optional
)
sig1 = session_ctx.sign(sec_nonce1, sk1)

# Verify partial signature.
signer_index = 0
session_ctx.valid_partial_sig?(sig1, pub_nonce1, signer_index)

# Signature aggregation.
sig = session_ctx.aggregate_partial_sigs([sig1, sig2])

# Verify signature.
Schnorr.valid_sig?(msg, agg_ctx.x_only_pubkey, sig.encode)
```

## Note

This library changes the following functions of `ecdsa` gem in `lib/schnorr/ec_point_ext.rb`.

* `ECDSA::Point` class has following two instance methods.
  * `#has_even_y?` check the y-coordinate of this point is an even.
  * `#encode(only_x = false)` encode this point into a binary string.
* `ECDSA::Format::PointOctetString#decode`:
  * supports decoding only from x coordinate.
  * decode 33 bytes of zeros as infinity points.
