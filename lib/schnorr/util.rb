module Schnorr
  module Util

    # Check whether +str+ is hex string or not.
    # @param [String] str string.
    # @return [Boolean]
    def hex_string?(str)
      return false if str.bytes.any? { |b| b > 127 }
      return false if str.length % 2 != 0
      hex_chars = str.chars.to_a
      hex_chars.all? { |c| c =~ /[0-9a-fA-F]/ }
    end

    # If +str+ is a hex value, it is converted to binary. Otherwise, it is returned as is.
    # @param [String] str
    # @return [String]
    def hex2bin(str)
      hex_string?(str) ? [str].pack('H*') : str
    end

    # Convert +str+ to the point of elliptic curve.
    # @param [String] str A byte string for point.
    # @return [ECDSA::Point]
    def string2point(str)
      ECDSA::Format::PointOctetString.decode(str, GROUP)
    end
  end
end