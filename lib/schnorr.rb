require 'ecdsa'
require 'securerandom'
require_relative 'schnorr/ec_point_ext'
require_relative 'schnorr/signature'

module Schnorr
  module_function

  GROUP = ECDSA::Group::Secp256k1

  # Generate schnorr signature.
  # @param message (String) A message to be signed with binary format.
  # @param private_key (String) The private key with binary format.
  # @param aux_rand (String) The auxiliary random data with binary format.
  # If not specified, random data is not used and the private key is used to calculate the nonce.
  # @return (Schnorr::Signature)
  def sign(message, private_key, aux_rand = nil)
    raise 'The message must be a 32-byte array.' unless message.bytesize == 32

    d0 = private_key.unpack1('H*').to_i(16)
    raise 'private_key must be an integer in the range 1..n-1.' unless 0 < d0 && d0 <= (GROUP.order - 1)
    raise 'aux_rand must be 32 bytes.' if !aux_rand.nil? && aux_rand.bytesize != 32

    p = GROUP.new_point(d0)
    d = p.has_even_y? ? d0 : GROUP.order - d0

    t = aux_rand.nil? ? d : d ^ tagged_hash('BIP0340/aux', aux_rand).unpack1('H*').to_i(16)
    t = ECDSA::Format::IntegerOctetString.encode(t, GROUP.byte_length)

    k0 = ECDSA::Format::IntegerOctetString.decode(tagged_hash('BIP0340/nonce', t + p.encode(true) + message)) % GROUP.order
    raise 'Creation of signature failed. k is zero' if k0.zero?

    r = GROUP.new_point(k0)
    k = r.has_even_y? ? k0 : GROUP.order - k0
    e = create_challenge(r.x, p, message)

    sig = Schnorr::Signature.new(r.x, (k + e * d) % GROUP.order)
    raise 'The created signature does not pass verification.' unless valid_sig?(message, p.encode(true), sig.encode)

    sig
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

  # Verifies the given {Signature} and raises an {InvalidSignatureError} if it is invalid.
  # @param message (String) A message to be signed with binary format.
  # @param public_key (String) The public key with binary format.
  # @param signature (String) The signature with binary format.
  # @return (Boolean)
  def check_sig!(message, public_key, signature)
    raise InvalidSignatureError, 'The message must be a 32-byte array.' unless message.bytesize == 32
    raise InvalidSignatureError, 'The public key must be a 32-byte array.' unless public_key.bytesize == 32

    sig = Schnorr::Signature.decode(signature)
    pubkey = ECDSA::Format::PointOctetString.decode_from_x(public_key, GROUP)
    field = GROUP.field

    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is zero.' if sig.r.zero?
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is zero.' if sig.s.zero?
    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is larger than field size.' if sig.r >= field.prime
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is larger than group order.' if sig.s >= GROUP.order

    e = create_challenge(sig.r, pubkey, message)

    r = GROUP.new_point(sig.s) + pubkey.multiply_by_scalar(GROUP.order - e)

    if r.infinity? || !r.has_even_y? || r.x != sig.r
      raise Schnorr::InvalidSignatureError, 'signature verification failed.'
    end

    true
  end

  # create signature digest.
  # @param (Integer) x a x coordinate for R.
  # @param (ECDSA::Point) p a public key.
  # @return (Integer) digest e.
  def create_challenge(x, p, message)
    r_x = ECDSA::Format::IntegerOctetString.encode(x, GROUP.byte_length)
    (ECDSA.normalize_digest(tagged_hash('BIP0340/challenge', r_x + p.encode(true) + message), GROUP.bit_length)) % GROUP.order
  end

  # Generate tagged hash value.
  # @param (String) tag tag value.
  # @param (String) msg the message to be hashed.
  # @return (String) the hash value with binary format.
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
      return self**x unless y

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
