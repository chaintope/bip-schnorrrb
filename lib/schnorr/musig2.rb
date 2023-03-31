require_relative 'musig2/context/key_agg'

module Schnorr
  module MuSig2
    extend Util

    class Error < StandardError
    end

    module_function

    # Sort the list of public keys in lexicographical order.
    # @param [Array(String)] pubkeys An array of public keys.
    # @return [Array(String)] Sorted public keys with hex format.
    def sort_pubkeys(pubkeys)
      pubkeys.map{|p| hex_string?(p) ? p : p.unpack1('H*')}.sort
    end

    # Compute aggregate public key.
    # @param [Array[String]] pubkeys An array of public keys.
    # @return [Schnorr::MuSig2::KeyAggContext]
    def aggregate(pubkeys)
      pubkeys = pubkeys.map do |p|
        pubkey = hex_string?(p) ? [p].pack('H*') : p
        raise ArgumentError, "Public key must be 33 bytes." unless pubkey.bytesize == 33
        pubkey
      end
      pk2 = second_key(pubkeys)
      q = ECDSA::Ext::JacobianPoint.infinity_point(GROUP)
      l = hash_keys(pubkeys)
      pubkeys.each do |p|
        begin
          point = ECDSA::Format::PointOctetString.decode(p, GROUP).to_jacobian
        rescue ECDSA::Format::DecodeError
          raise ArgumentError, 'Invalid public key.'
        end
        coeff = p == pk2 ? 1 : Schnorr.tagged_hash('KeyAgg coefficient', l + p).unpack1('H*').to_i(16)
        q += point * coeff
      end
      KeyAggContext.new(q.to_affine, 1, 0)
    end

    def second_key(pubkeys)
      pubkeys[1..].each do |p|
        return p unless p == pubkeys[0]
      end
      ['00'].pack("H*") * 33
    end
    private_class_method :second_key

    # Compute
    def hash_keys(pubkeys)
      Schnorr.tagged_hash('KeyAgg list', pubkeys.join)
    end
    private_class_method :hash_keys
  end
end