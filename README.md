# bip-schnorrrb [![Build Status](https://travis-ci.org/chaintope/bip-schnorrrb.svg?branch=master)](https://travis-ci.org/chaintope/bip-schnorrrb) [![Gem Version](https://badge.fury.io/rb/bip-schnorr.svg)](https://badge.fury.io/rb/bip-schnorr) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE) 

This is a Ruby implementation of the Schnorr signature scheme over the elliptic curve. 
This implementation relies on the [ecdsa gem](https://github.com/DavidEGrayson/ruby_ecdsa) for operate elliptic curves.

The code is based upon the initial proposal of Pieter Wuille's [bip-schnorr](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki).

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

### Singing

```ruby
require 'schnorr'

private_key = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF

message = ['5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C'].pack('H*')

# create signature
signature = Schnorr.sign(message, private_key)

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

signature = ['e7758e20e67a0607433cf8a1f0383a02c7b56792aab71763173ab7085cab8768082aae167787bc3572d15176dc26c073d9b03726aed0b59c728aa6538dc03d57'].pack('H*')

message = ['5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C'].pack('H*')

# verify signature.(result is true or false)
result = Schnorr.valid_sig?(message, public_key, signature) 

# signature convert to Signature object
sig = Schnorr::Signature.decode(signature) 
```

## Note

This library changes the following functions of `ecdsa` gem in `lib/schnorr/ec_point_ext.rb`.

* `ECDSA::Point` class has following two instance methods.
    * `#has_square_y?` check this point does not infinity and square?(y coordinate)
    * `#square?(x)` check whether `x` is a quadratic residue modulo p.
* `ECDSA::Format::PointOctetString#decode` supports decoding only from x coordinate.