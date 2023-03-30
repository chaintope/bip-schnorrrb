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
  end
end