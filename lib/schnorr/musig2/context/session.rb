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
        @agg_ctx = MuSig2.aggregate_with_tweaks(@pubkeys, @tweaks, @modes)
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
      # @return [String] Partial signature with hex format.
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
      # @param [String] pub_nonce A public nonce.
      # @param [Integer] signer_index The index of signer.
      # @return [Boolean]
      def valid_partial_sig?(partial_sig, pub_nonce, signer_index)
        begin
          partial_sig = hex2bin(partial_sig)
          pub_nonce = hex2bin(pub_nonce)
          s = partial_sig.bti
          return false if s >= GROUP.order
          r1 = ECDSA::Format::PointOctetString.decode(pub_nonce[0...33], GROUP).to_jacobian
          r2 = ECDSA::Format::PointOctetString.decode(pub_nonce[33...66], GROUP).to_jacobian
          r_s = (r1 + r2 * b).to_affine
          r_s = r.has_even_y? ? r_s : r_s.negate
          pk = ECDSA::Format::PointOctetString.decode(pubkeys[signer_index], GROUP)
          a = key_agg_coeff(pubkeys, pubkeys[signer_index])
          g = agg_ctx.q.has_even_y? ? 1 : GROUP.order - 1
          g = (g * agg_ctx.gacc) % GROUP.order
          GROUP.generator.to_jacobian * s == r_s.to_jacobian + pk.to_jacobian * (e * a * g % GROUP.order)
        rescue ECDSA::Format::DecodeError => e
          raise ArgumentError, e
        end
      end

      # Aggregate partial signatures.
      # @param [Array] partial_sigs An array of partial signature.
      # @return [Schnorr::Signature] An aggregated signature.
      def aggregate_partial_sigs(partial_sigs)
        s = 0
        partial_sigs.each do |partial_sig|
          s_i = hex2bin(partial_sig).bti
          raise ArgumentError, 'Invalid partial sig.' if s_i >= GROUP.order
          s = (s + s_i) % GROUP.order
        end
        g = agg_ctx.q.has_even_y? ? 1 : GROUP.order - 1
        s = (s + e * g * agg_ctx.tacc) % GROUP.order
        Schnorr::Signature.new(r.x, s)
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
