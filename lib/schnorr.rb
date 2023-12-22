require 'ecdsa_ext'
require 'securerandom'
require_relative 'schnorr/util'
require_relative 'schnorr/ec_point_ext'
require_relative 'schnorr/signature'
require_relative 'schnorr/musig2'

module Schnorr
  extend Util
  module_function

  GROUP = ECDSA::Group::Secp256k1
  DEFAULT_AUX = ([0x00] * 32).pack('C*')

  # Generate schnorr signature.
  # @param [String] message A message to be signed with binary format.
  # @param [String] private_key The private key(binary format or hex format).
  # @param [String] aux_rand The auxiliary random data(binary format or hex format).
  # If aux_rand is nil, it is treated the same as an all-zero one.
  # See BIP-340 "Default Signing" for a full explanation of this argument and for guidance if randomness is expensive.
  # @return [Schnorr::Signature]
  def sign(message, private_key, aux_rand = nil)
    private_key = private_key.unpack1('H*') unless hex_string?(private_key)

    d0 = private_key.to_i(16)
    raise 'private_key must be an integer in the range 1..n-1.' unless 0 < d0 && d0 <= (GROUP.order - 1)
    if aux_rand
      aux_rand = [aux_rand].pack("H*") if hex_string?(aux_rand)
      raise 'aux_rand must be 32 bytes.' unless aux_rand.bytesize == 32
    else
      aux_rand = DEFAULT_AUX
    end

    p = (GROUP.generator.to_jacobian * d0).to_affine
    d = p.has_even_y? ? d0 : GROUP.order - d0

    t = aux_rand.nil? ? d : d ^ tagged_hash('BIP0340/aux', aux_rand).bti
    t = ECDSA::Format::IntegerOctetString.encode(t, GROUP.byte_length)

    k0 = ECDSA::Format::IntegerOctetString.decode(tagged_hash('BIP0340/nonce', t + p.encode(true) + message)) % GROUP.order
    raise 'Creation of signature failed. k is zero' if k0.zero?

    r = (GROUP.generator.to_jacobian * k0).to_affine
    k = r.has_even_y? ? k0 : GROUP.order - k0
    e = create_challenge(r.x, p, message)

    sig = Schnorr::Signature.new(r.x, (k + e * d) % GROUP.order)
    raise 'The created signature does not pass verification.' unless valid_sig?(message, p.encode(true), sig.encode)

    sig
  end

  # Verifies the given {Signature} and returns true if it is valid.
  # @param [String] message A message to be signed with binary format.
  # @param [String] public_key The public key with binary format.
  # @param [String] signature The signature with binary format.
  # @return [Boolean] whether signature is valid.
  def valid_sig?(message, public_key, signature)
    check_sig!(message, public_key, signature)
  rescue InvalidSignatureError, ECDSA::Format::DecodeError
    false
  end

  # Verifies the given {Signature} and raises an {InvalidSignatureError} if it is invalid.
  # @param [String] message A message to be signed with binary format.
  # @param [String] public_key The public key with binary format.
  # @param [String] signature The signature with binary format.
  # @return [Boolean]
  def check_sig!(message, public_key, signature)
    message = hex2bin(message)
    public_key = hex2bin(public_key)
    public_key = [public_key].pack('H*') if hex_string?(public_key)
    raise InvalidSignatureError, 'The public key must be a 32-byte array.' unless public_key.bytesize == 32

    sig = Schnorr::Signature.decode(signature)
    pubkey = ECDSA::Format::PointOctetString.decode_from_x(public_key, GROUP)
    field = GROUP.field

    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is zero.' if sig.r.zero?
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is zero.' if sig.s.zero?
    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is larger than field size.' if sig.r >= field.prime
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is larger than group order.' if sig.s >= GROUP.order

    e = create_challenge(sig.r, pubkey, message)
    r = (GROUP.generator.to_jacobian * sig.s + pubkey.to_jacobian * (GROUP.order - e)).to_affine

    if r.infinity? || !r.has_even_y? || r.x != sig.r
      raise Schnorr::InvalidSignatureError, 'signature verification failed.'
    end

    true
  end

  # create signature digest.
  # @param [Integer] x A x coordinate for R.
  # @param [ECDSA::Point] p A public key.
  # @return [Integer] digest e.
  def create_challenge(x, p, message)
    r_x = ECDSA::Format::IntegerOctetString.encode(x, GROUP.byte_length)
    (ECDSA.normalize_digest(tagged_hash('BIP0340/challenge', r_x + p.encode(true) + message), GROUP.bit_length)) % GROUP.order
  end

  # Generate tagged hash value.
  # @param [String] tag tag value.
  # @param [String] msg the message to be hashed.
  # @return [String] the hash value with binary format.
  def tagged_hash(tag, msg)
    tag_hash = Digest::SHA256.digest(tag)
    Digest::SHA256.digest(tag_hash + tag_hash + msg)
  end

  class ::String

    # Convert binary to integer.
    # @return [Integer]
    def bti
      self.unpack1('H*').to_i(16)
    end

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
