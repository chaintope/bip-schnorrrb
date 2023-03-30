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

## Note

This library changes the following functions of `ecdsa` gem in `lib/schnorr/ec_point_ext.rb`.

* `ECDSA::Point` class has following two instance methods.
    * `#has_even_y?` check the y-coordinate of this point is an even.
    * `#encode(only_x = false)` encode this point into a binary string.
* `ECDSA::Format::PointOctetString#decode` supports decoding only from x coordinate.
