require_relative 'musig2/context/key_agg'
require_relative 'musig2/context/session'

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
        pubkey = hex2bin(p)
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
        coeff = p == pk2 ? 1 : Schnorr.tagged_hash('KeyAgg coefficient', l + p).bti
        q += point * coeff
      end
      KeyAggContext.new(q.to_affine, 1, 0)
    end

    # Compute aggregate public key with tweaks.
    # @param [Array[String]] pubkeys An array of public keys.
    # @param [Array] tweaks An array of tweak.
    # @param [Array] modes An array of x_only mode.
    # @return [Schnorr::MuSig2::KeyAggContext]
    def aggregate_with_tweaks(pubkeys, tweaks, modes)
      raise ArgumentError, 'tweaks and modes must be same length' unless tweaks.length == modes.length
      agg_ctx = aggregate(pubkeys)
      tweaks.each.with_index do |tweak, i|
        tweak = hex2bin(tweak)
        raise ArgumentError, 'tweak value must be 32 bytes' unless tweak.bytesize == 32
        agg_ctx = agg_ctx.apply_tweak(tweak, modes[i])
      end
      agg_ctx
    end

    # Generate nonce.
    # @param [String] pk The public key (33 bytes).
    # @param [String] sk (Optional) The secret key string (32 bytes).
    # @param [String] agg_pubkey (Optional) The aggregated public key (32 bytes).
    # @param [String] msg (Optional) The message to be signed.
    # @param [String] extra_in (Optional) The auxiliary input.
    # @param [String] rand (Optional) A 32-byte array freshly drawn uniformly at random.
    # @return [Array(String)] The array of sec nonce and pub nonce with hex format.
    def gen_nonce(pk: , sk: nil, agg_pubkey: nil, msg: nil, extra_in: nil, rand: SecureRandom.bytes(32))
      rand = hex2bin(rand)
      raise ArgumentError, 'The rand must be 32 bytes.' unless rand.bytesize == 32

      pk = hex2bin(pk)
      raise ArgumentError, 'The pk must be 33 bytes.' unless pk.bytesize == 33

      rand = if sk.nil?
               rand
             else
               sk = hex2bin(sk)
               raise ArgumentError, "The sk must be 32 bytes." unless sk.bytesize == 32
               gen_aux(sk, rand)
             end
      agg_pubkey = if agg_pubkey
                     agg_pubkey = hex2bin(agg_pubkey)
                     raise ArgumentError, 'The agg_pubkey must be 33 bytes.' unless agg_pubkey.bytesize == 32
                     agg_pubkey
                   else
                     ''
                   end
      msg_prefixed = if msg.nil?
                       [0].pack('C')
                     else
                       msg = hex2bin(msg)
                       [1, msg.bytesize].pack('CQ>') + msg
                     end
      extra_in = extra_in ? hex2bin(extra_in) : ''

      k1 = nonce_hash(rand, pk, agg_pubkey, 0, msg_prefixed, extra_in)
      k1_i = k1.bti % GROUP.order
      k2 = nonce_hash(rand, pk, agg_pubkey, 1, msg_prefixed, extra_in)
      k2_i = k2.bti % GROUP.order
      raise ArgumentError, 'k1 must not be zero.' if k1_i.zero?
      raise ArgumentError, 'k2 must not be zero.' if k2_i.zero?

      r1 = (GROUP.generator.to_jacobian * k1_i).to_affine
      r2 = (GROUP.generator.to_jacobian * k2_i).to_affine
      pub_nonce = r1.encode + r2.encode
      sec_nonce = k1 + k2 + pk
      [sec_nonce.unpack1('H*'), pub_nonce.unpack1('H*')]
    end

    # Aggregate public nonces.
    # @param [Array] nonces Array of public nonce. Each public nonce consists 66 bytes.
    # @return [String] An aggregated public nonce(R1 || R2) with hex format.
    def aggregate_nonce(nonces)
      2.times.map do |i|
        r = GROUP.generator.to_jacobian.infinity_point
        nonces = nonces.each do |nonce|
          nonce = hex2bin(nonce)
          raise ArgumentError, "" unless nonce.bytesize == 66
          begin
            p = ECDSA::Format::PointOctetString.decode(nonce[(i * 33)...(i + 1)*33], GROUP).to_jacobian
            raise ArgumentError, 'Public nonce is infinity' if p.infinity?
          rescue ECDSA::Format::DecodeError
            raise ArgumentError, "Invalid public nonce."
          end
          r += p
        end
        r.to_affine.encode.unpack1('H*')
      end.join
    end

    # Generate deterministic signature.
    # @param [String] sk The secret key string (32 bytes).
    # @param [String] agg_other_nonce Other aggregated nonce.
    # @param [Array] pubkeys An array of public keys.
    # @param [String] msg The message to be signed.
    # @param [Array(String)] tweaks (Optional) An array of tweak value.
    # @param [Array(Boolean)] modes (Optional) An array of tweak mode.
    # @param [String] rand (Optional) A 32-byte array freshly drawn uniformly at random.
    # @return [Array] [public nonce, partial signature]
    def deterministic_sign(sk, agg_other_nonce, pubkeys, msg, tweaks: [], modes: [], rand: nil)
      raise ArgumentError, 'The tweaks and modes arrays must have the same length.' unless tweaks.length == modes.length
      sk = hex2bin(sk)
      msg = hex2bin(msg)
      agg_other_nonce = hex2bin(agg_other_nonce)
      sk_ = rand ? gen_aux(sk, hex2bin(rand)) : sk
      agg_ctx = aggregate_with_tweaks(pubkeys, tweaks, modes)
      agg_pk = [agg_ctx.x_only_pubkey].pack("H*")
      k1 = deterministic_nonce_hash(sk_, agg_other_nonce, agg_pk, msg, 0).bti
      k2 = deterministic_nonce_hash(sk_, agg_other_nonce, agg_pk, msg, 1).bti
      r1 = (GROUP.generator.to_jacobian * k1).to_affine
      r2 = (GROUP.generator.to_jacobian * k2).to_affine
      raise ArgumentError, 'R1 must not be infinity.' if r1.infinity?
      raise ArgumentError, 'R2 must not be infinity.' if r2.infinity?
      pub_nonce = r1.encode + r2.encode
      pk = (GROUP.generator.to_jacobian * sk.bti).to_affine
      sec_nonce = ECDSA::Format::IntegerOctetString.encode(k1, GROUP.byte_length) +
        ECDSA::Format::IntegerOctetString.encode(k2, GROUP.byte_length) + pk.encode
      agg_nonce = aggregate_nonce([pub_nonce, agg_other_nonce])
      ctx = SessionContext.new(agg_nonce, pubkeys, msg, tweaks, modes)
      sig = ctx.sign(sec_nonce, sk)
      [pub_nonce.unpack1('H*'), sig]
    end

    def second_key(pubkeys)
      pubkeys[1..].each do |p|
        return p unless p == pubkeys[0]
      end
      ['00'].pack("H*") * 33
    end

    # Compute
    def hash_keys(pubkeys)
      Schnorr.tagged_hash('KeyAgg list', pubkeys.join)
    end

    def nonce_hash(rand, pk, agg_pubkey, i, prefixed_msg, extra_in)
      buf = ''
      buf << rand
      buf << [pk.bytesize].pack('C') + pk
      buf << [agg_pubkey.bytesize].pack('C') + agg_pubkey
      buf << prefixed_msg
      buf << [extra_in.bytesize].pack('N') + extra_in
      buf << [i].pack('C')
      Schnorr.tagged_hash('MuSig/nonce', buf)
    end
    private_class_method :nonce_hash

    def gen_aux(sk, rand)
      sk.unpack('C*').zip(Schnorr.tagged_hash('MuSig/aux', rand).
        unpack('C*')).map{|a, b| a ^ b}.pack('C*')
    end
    private_class_method :gen_aux

    def deterministic_nonce_hash(sk_, agg_other_nonce, agg_pk, msg, i)
      buf = ''
      buf << sk_
      buf << agg_other_nonce
      buf << agg_pk
      buf << [msg.bytesize].pack('Q>')
      buf << msg
      buf << [i].pack('C')
      Schnorr.tagged_hash('MuSig/deterministic/nonce', buf)
    end
    private_class_method :deterministic_nonce_hash
  end
end