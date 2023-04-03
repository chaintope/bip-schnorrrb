module Schnorr
  module MuSig2
    class KeyAggContext
      include Schnorr::Util

      attr_reader :q, :gacc, :tacc

      # @param [ECDSA::Point] q Aggregated point.
      # @param [Integer] gacc
      # @param [Integer] tacc
      def initialize(q, gacc, tacc)
        raise ArgumentError, 'The gacc must be Integer.' unless gacc.is_a?(Integer)
        raise ArgumentError, 'The tacc must be Integer.' unless tacc.is_a?(Integer)
        raise ArgumentError, 'The q must be ECDSA::Point.' unless q.is_a?(ECDSA::Point)
        @q = q
        @gacc = gacc
        @tacc = tacc
      end

      # Get x-only public key.
      # @return [String] x-only public key(hex format).
      def x_only_pubkey
        q.encode(true).unpack1('H*')
      end

      # Tweaking the aggregate public key
      # @param [String] tweak 32 bytes tweak value.
      # @param [Boolean] is_xonly_t Tweak mode.
      # @return [Schnorr::MuSig2::KeyAggContext] Tweaked context.
      def apply_tweak(tweak, is_xonly_t)
        tweak = hex2bin(tweak)
        raise ArgumentError, 'The tweak must be a 32-bytes.' unless tweak.bytesize == 32

        g = is_xonly_t && !q.has_even_y? ? q.group.order - 1 : 1
        t = tweak.unpack1('H*').to_i(16)

        raise ArgumentError, 'The tweak must be less than curve order.' if t >= q.group.order
        new_q = (q.to_jacobian * g + q.group.generator.to_jacobian * t).to_affine
        raise ArgumentError, 'The result of tweaking cannot be infinity.' if new_q.infinity?
        new_gacc = (g * gacc) % q.group.order
        new_tacc = (t + g * tacc) % q.group.order
        KeyAggContext.new(new_q, new_gacc, new_tacc)
      end
    end
  end
end