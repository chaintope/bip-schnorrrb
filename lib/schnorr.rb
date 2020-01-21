require 'ecdsa'
require 'securerandom'
require_relative 'schnorr/ec_point_ext'
require_relative 'schnorr/signature'

module Schnorr

  module_function

  GROUP = ECDSA::Group::Secp256k1

  # Generate schnorr signature.
  # @param message (String) A message to be signed with binary format.
  # @param private_key (Integer) The private key.
  # (The number of times to add the generator point to itself to get the public key.)
  # @return (Schnorr::Signature)
  def sign(message, private_key)
    raise 'The message must be a 32-byte array.' unless message.bytesize == 32
    p = GROUP.new_point(private_key)
    seckey = p.has_square_y? ? private_key : GROUP.order - private_key
    secret = ECDSA::Format::IntegerOctetString.encode(seckey, GROUP.byte_length)

    k0 = ECDSA::Format::IntegerOctetString.decode(tagged_hash('BIPSchnorrDerive', secret + message)) % GROUP.order
    raise 'Creation of signature failed. k is zero' if k0.zero?

    r = GROUP.new_point(k0)

    k = r.has_square_y? ? k0 : GROUP.order - k0

    e = create_challenge(r.x, p, message, GROUP)

    Schnorr::Signature.new(r.x, (k + e * seckey) % GROUP.order)
  end

  # Verifies the given {Signature} and returns true if it is valid.
  # @param message (String) A message to be signed with binary format.
  # @param public_key (String) The public key with binary format.
  # @param signature (String) The signature with binary format.
  # @return (Boolean) whether signature is valid.
  def valid_sig?(message, public_key, signature)
    check_sig!(message, public_key, signature)
  rescue InvalidSignatureError, ECDSA::Format::DecodeError
    false
  end

  # Batch verification
  # @param messages (Array[String]) The array of message with binary format.
  # @param public_keys (Array[String]) The array of public key with binary format.
  # @param signatures (Array[String]) The array of signatures with binary format.
  # @return (Boolean) whether signature is valid.
  def valid_sigs?(messages, public_keys, signatures)
    raise ArgumentError, 'all parameters must be an array with the same length.' if messages.size != public_keys.size || public_keys.size != signatures.size
    field = GROUP.field
    pubkeys = public_keys.map{|p| ECDSA::Format::PointOctetString.decode(p, GROUP)}
    sigs = signatures.map do|signature|
      sig = Schnorr::Signature.decode(signature)
      raise Schnorr::InvalidSignatureError, 'Invalid signature: r is not in the field.' unless field.include?(sig.r)
      raise Schnorr::InvalidSignatureError, 'Invalid signature: s is not in the field.' unless field.include?(sig.s)
      raise Schnorr::InvalidSignatureError, 'Invalid signature: r is zero.' if sig.r.zero?
      raise Schnorr::InvalidSignatureError, 'Invalid signature: s is zero.' if sig.s.zero?
      sig
    end
    left = 0
    right = nil
    pubkeys.each_with_index do |pubkey, i|
      r = sigs[i].r
      s = sigs[i].s
      e = create_challenge(r, pubkey, messages[i], GROUP)
      c = field.mod(r.pow(3) + 7)
      y = c.pow((field.prime + 1)/4, field.prime)
      raise Schnorr::InvalidSignatureError, 'c is not equal to y^2.' unless c == y.pow(2, field.prime)
      r_point = ECDSA::Point.new(GROUP, r, y)
      if i == 0
        left = s
        right = r_point + pubkey.multiply_by_scalar(e)
      else
        a = 1 + SecureRandom.random_number(GROUP.order - 1)
        left += (a * s)
        right += (r_point.multiply_by_scalar(a) + pubkey.multiply_by_scalar(a * e))
      end
    end
    GROUP.new_point(left) == right
  rescue InvalidSignatureError, ECDSA::Format::DecodeError
    false
  end

  # Verifies the given {Signature} and raises an {InvalidSignatureError} if it is invalid.
  # @param message (String) A message to be signed with binary format.
  # @param public_key (String) The public key with binary format.
  # @param signature (String) The signature with binary format.
  # @return (Boolean)
  def check_sig!(message, public_key, signature)
    sig = Schnorr::Signature.decode(signature)
    pubkey = ECDSA::Format::PointOctetString.decode(public_key, GROUP)
    field = GROUP.field

    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is not in the field.' unless field.include?(sig.r)
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is not in the field.' unless field.include?(sig.s)
    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is zero.' if sig.r.zero?
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is zero.' if sig.s.zero?
    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is larger than field size.' if sig.r >= field.prime
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is larger than group order.' if sig.s >= GROUP.order

    e = create_challenge(sig.r, pubkey, message, GROUP)

    r = GROUP.new_point(sig.s) + pubkey.multiply_by_scalar(GROUP.order - e)

    if r.infinity? || !r.has_square_y? || r.x != sig.r
      raise Schnorr::InvalidSignatureError, 'signature verification failed.'
    end

    true
  end

  # create signature digest.
  # @param (Integer) x a x coordinate for R.
  # @param (ECDSA::Point) p a public key.
  # @param (ECDSA::Group) group the group of elliptic curve.
  # @return (Integer) digest e.
  def create_challenge(x, p, message, group)
    r_x = ECDSA::Format::IntegerOctetString.encode(x, group.byte_length)
    p_x = ECDSA::Format::IntegerOctetString.encode(p.x, group.byte_length)
    (ECDSA.normalize_digest(tagged_hash('BIPSchnorr', r_x + p_x + message), group.bit_length)) % group.order
  end

  # Generate tagged hash value.
  def tagged_hash(tag, msg)
    tag_hash = Digest::SHA256.digest(tag)
    Digest::SHA256.digest(tag_hash + tag_hash + msg)
  end

  class ::Integer

    def to_hex
      hex = to_s(16)
      hex.rjust((hex.length / 2.0).ceil * 2, '0')
    end

    def method_missing(method, *args)
      return mod_pow(args[0], args[1]) if method == :pow && args.length < 3
      super
    end

    # alternative implementation of Integer#pow for ruby 2.4 and earlier.
    def mod_pow(x, y)
      return self ** x unless y
      b = self
      result = 1
      while x > 0
        result = (result * b) % y if (x & 1) == 1
        x >>= 1
        b = (b * b) % y
      end
      result
    end

  end

end
