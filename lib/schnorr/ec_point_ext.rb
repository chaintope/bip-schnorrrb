# ECDSA gem elliptic curve point extension for bip-schnorr.
module ECDSA
  class Point

    # Check the y-coordinate of this point is an even.
    # @return (Boolean) if even, return true.
    def has_even_y?
      y.even?
    end

    # Encode this point into a binary string.
    # @param (Boolean) only_x whether or not to encode only X-coordinate. default is false.
    def encode(only_x = false)
      if only_x
        ECDSA::Format::FieldElementOctetString.encode(x, group.field)
      else
        if infinity?
          "\x00" * 33
        else
          ECDSA::Format::PointOctetString.encode(self, {compression: true})
        end
      end
    end

  end

  module Format

    module PointOctetString

      def self.decode(string, group)
        string = string.dup.force_encoding('BINARY')

        raise DecodeError, 'Point octet string is empty.' if string.empty?

        if string.bytesize == 32
          decode_from_x(string, group)
        else
          case string[0].ord
          when 0
            check_length string, 33
            raise DecodeError, 'Unrecognized infinity point.' unless ['00' * 33].pack('H*') == string
            return group.infinity
          when 2
            decode_compressed string, group, 0
          when 3
            decode_compressed string, group, 1
          when 4
            decode_uncompressed string, group
          else
            raise DecodeError, 'Unrecognized start byte for point octet string: 0x%x' % string[0].ord
          end
        end
      end

      # decode from x coordinate.
      # @param (String) x_string X-coordinate binary string
      # @param (ECDSA::Group) group A group of elliptic curves to use.
      # @return (ECDSA::Point) decoded point.
      def self.decode_from_x(x_string, group)
        x = ECDSA::Format::FieldElementOctetString.decode(x_string, group.field)
        y_sq = group.field.mod(x.pow(3, group.field.prime) + 7)
        y = y_sq.pow((group.field.prime + 1)/4, group.field.prime)
        raise DecodeError, 'Public key not on the curve.' unless y.pow(2, group.field.prime) == y_sq
        finish_decode(x, y.even? ? y : group.field.prime - y, group)
      end

    end

  end
end
