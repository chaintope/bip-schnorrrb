module Schnorr
  module MuSig2
    class SessionContext
      include Schnorr::Util
      attr_reader :agg_nonce, :pubkeys, :tweaks, :modes, :msg, :r, :agg_ctx, :b

      # @param [String] agg_nonce
      # @param [Array(String)] pubkeys An array of public keys.
      # @param [String] msg A message to be signed.
      # @param [Array(String)] tweaks An array of tweaks(32 bytes).
      # @param [Array(Boolean)] modes An array of tweak mode(Boolean).
      def initialize(agg_nonce, pubkeys, msg, tweaks = [], modes = [])
        @agg_nonce = hex2bin(agg_nonce)
        @pubkeys = pubkeys.map do |pubkey|
          pubkey = hex2bin(pubkey)
          raise ArgumentError, 'pubkey must be 33 bytes' unless pubkey.bytesize == 33
          pubkey
        end
        @msg = hex2bin(msg)
        @tweaks = tweaks
        @modes = modes
        @modes.each do |mode|
          raise ArgumentError, 'mode must be Boolean.' unless [TrueClass, FalseClass].include?(mode.class)
        end
        ctx = KeyAggContext.new(MuSig2.aggregate(@pubkeys).q, 1, 0)
        @tweaks.each.with_index do |tweak, i|
          tweak = hex2bin(tweak)
          raise ArgumentError, 'tweak value must be 32 bytes' unless tweak.bytesize == 32
          ctx = ctx.apply_tweak(tweak, @modes[i])
        end
        @agg_ctx = ctx
        @b = Schnorr.tagged_hash('MuSig/noncecoef', @agg_nonce + agg_ctx.q.encode(true) + @msg).bti
        begin
          r1 = ECDSA::Format::PointOctetString.decode(@agg_nonce[0...33], GROUP).to_jacobian
          r2 = ECDSA::Format::PointOctetString.decode(@agg_nonce[33...66], GROUP).to_jacobian
        rescue ECDSA::Format::DecodeError
          raise ArgumentError, 'Invalid agg_nonce'
        end
        r = (r1 + r2 * @b).to_affine
        @r = r.infinity? ? GROUP.generator : r
      end

      # Get message digest.
      # @return [Integer]
      def e
        Schnorr.tagged_hash('BIP0340/challenge', r.encode(true) + agg_ctx.q.encode(true) + msg).bti
      end

      # Create partial signature.
      # @param [String] nonce The secret nonce.
      # @param [String] sk The secret key.
      # @return
      def sign(nonce, sk)
        nonce = hex2bin(nonce)
        sk = hex2bin(sk)
        k1 = nonce[0...32].bti
        k2 = nonce[32...64].bti
        raise ArgumentError, 'first nonce value is out of range.' if k1 <= 0 || GROUP.order <= k1
        raise ArgumentError, 'second nonce value is out of range.' if k2 <= 0 || GROUP.order <= k2
        k1 = r.has_even_y? ? k1 : GROUP.order - k1
        k2 = r.has_even_y? ? k2 : GROUP.order - k2
        d = sk.bti
        raise ArgumentError, 'secret key value is out of range.' if d <= 0 || GROUP.order <= d
        p = (GROUP.generator.to_jacobian * d).to_affine
        raise ArgumentError, 'Public key does not match nonce_gen argument' unless p.encode == nonce[64...97]
        a = key_agg_coeff(pubkeys, p.encode)
        g = agg_ctx.q.has_even_y? ? 1 : GROUP.order - 1
        d = (g * agg_ctx.gacc * d)  % GROUP.order
        s = (k1 + b * k2 + e * a * d) % GROUP.order
        r1 = (GROUP.generator.to_jacobian * k1).to_affine
        r2 = (GROUP.generator.to_jacobian * k2).to_affine
        raise ArgumentError, 'R1 can not be infinity.' if r1.infinity?
        raise ArgumentError, 'R2 can not be infinity.' if r2.infinity?
        ECDSA::Format::IntegerOctetString.encode(s, GROUP.byte_length).unpack1('H*')
      end

      # Verify partial signature.
      # @param [String] partial_sig The partial signature.
      # @param [String] nonces An array of public nonce.
      # @param [Integer] signer_index The index of signer.
      # @return [Boolean]
      def valid_partial_sig?(partial_sig, nonces, signer_index)
        pub_nonce = [MuSig2.aggregate_nonce(nonces)].pack('H*')
        partial_sig = hex2bin(partial_sig)
        s = partial_sig.bti
        return false if s >= GROUP.order
        r1 = ECDSA::Format::PointOctetString.decode(pub_nonce[0...33], GROUP).to_jacobian
        r2 = ECDSA::Format::PointOctetString.decode(pub_nonce[33...66], GROUP).to_jacobian
        r = (r1 + r2 * b).to_affine
        r = !r.infinity? && r.has_even_y? ? r : r.negate
        pk = ECDSA::Format::PointOctetString.decode(pubkeys[signer_index], GROUP)
        a = key_agg_coeff(pubkeys, pubkeys[signer_index])
        g = agg_ctx.q.has_even_y? ? 1 : GROUP.order - 1
        g = (g * agg_ctx.gacc) % GROUP.order
        GROUP.generator.to_jacobian * s == r + pk * (e * a * g % GROUP.order)
      end

      private

      def key_agg_coeff(pubkeys, public_key)
        raise ArgumentError, 'The signer\'s pubkey must be included in the list of pubkeys.' unless pubkeys.include?(public_key)
        l = MuSig2.hash_keys(pubkeys)
        pk2 = MuSig2.second_key(pubkeys)
        public_key == pk2 ? 1 : Schnorr.tagged_hash('KeyAgg coefficient', l + public_key).bti
      end
    end
  end
end
