module Schnorr

  class InvalidSignatureError < StandardError; end

  # Instances of this class represents Schnorr signatures,
  # which are simply a pair of integers named `r` and `s`.
  class Signature

    attr_reader :r
    attr_reader :s

    # @param r (Integer) the value of r.
    # @param s (Integer) the value of s.
    def initialize(r, s)
      @r, @s = r, s
      r.is_a?(Integer) or raise ArgumentError, 'r is not an integer.'
      s.is_a?(Integer) or raise ArgumentError, 's is not an integer.'
    end

    # Parse a string to a {Signature}.
    # @param string (String) signature string with binary format.
    # @return (Signature) signature instance.
    def self.decode(string)
      raise InvalidSignatureError, 'Invalid schnorr signature length.' unless string.bytesize == 64
      r = string[0...32].bti
      s = string[32..-1].bti
      new(r, s)
    end

    # Encode signature to string.
    # @return (String) encoded signature.
    def encode
      ECDSA::Format::IntegerOctetString.encode(r, 32) + ECDSA::Format::IntegerOctetString.encode(s, 32)
    end

    # Check whether same signature or not.
    # @return [Boolean]
    def ==(other)
      return false unless other.is_a?(Signature)
      r == other.r && s == other.s
    end
  end

end