require 'spec_helper'

RSpec.describe Schnorr::MuSig2 do

  describe 'Test Vector' do
    let(:pubkeys) { vector['pubkeys'] }
    let(:sk) { vector['sk'] }
    let(:sec_nonces) { vector['secnonces'] }
    let(:pub_nonces) { vector['pnonces'] }
    let(:agg_nonces) { vector['aggnonces'] }
    let(:msgs) { vector['msgs'] }

    describe 'key_sort_vectors' do
      let(:vector) {  read_json('key_sort_vectors.json') }

      it do
        sorted_keys = described_class.sort_pubkeys(pubkeys)
        expect(sorted_keys).to eq(vector['sorted_pubkeys'])
      end
    end

    describe 'key_agg_vectors' do
      let(:vector) {  read_json('key_agg_vectors.json') }

      context 'Valid case' do
        it do
          vector['valid_test_cases'].each do |keys|
            pubkey_candidates = keys['key_indices'].map{|i| pubkeys[i] }
            agg_key_ctx = described_class.aggregate(pubkey_candidates)
            expect(agg_key_ctx.x_only_pubkey).to eq(keys['expected'].downcase)
          end
        end
      end

      context 'Error case' do
        it do
          tweaks = vector['tweaks']
          vector['error_test_cases'].each do |error|
            pubkey_candidates = error['key_indices'].map{|i| pubkeys[i] }
            if error['error']['type'] == 'invalid_contribution'
              expect{described_class.aggregate(pubkey_candidates)}.to raise_error(ArgumentError)
            else
              agg_key_ctx = described_class.aggregate(pubkey_candidates)
              error['tweak_indices'].each do |index|
                tweak = tweaks[index]
                is_xonly = error['is_xonly'][index]
                expect{agg_key_ctx.apply_tweak(tweak, is_xonly)}.to raise_error(ArgumentError, error['error']['comment'])
              end
            end
          end
        end
      end
    end

    describe 'nonce_gen_vectors' do
      let(:vector) { read_json('nonce_gen_vectors.json') }
      it do
        vector['test_cases'].each do |test|
          sec_nonce, pub_nonce = described_class.gen_nonce(
            pk: test['pk'],
            sk: test['sk'],
            agg_pubkey: test['aggpk'],
            msg: test['msg'],
            extra_in: test['extra_in'],
            rand: test['rand_'])
          expect(sec_nonce).to eq(test['expected_secnonce'].downcase)
          expect(pub_nonce).to eq(test['expected_pubnonce'].downcase)
        end
      end
    end

    describe 'nonce_agg_vectors' do
      let(:vector) { read_json('nonce_agg_vectors.json') }
      it do
        vector['valid_test_cases'].each do |valid|
          target_pub_nonces = valid['pnonce_indices'].map {|i|pub_nonces[i]}
          expect(described_class.aggregate_nonce(target_pub_nonces)).to eq(valid['expected'].downcase)
        end
        vector['error_test_cases'].each do |error|
          target_pub_nonces = error['pnonce_indices'].map {|i|pub_nonces[i]}
          expect{described_class.aggregate_nonce(target_pub_nonces)}.to raise_error(ArgumentError)
        end
      end
    end

    describe 'sign_verify_vectors' do
      let(:vector) { read_json('sign_verify_vectors.json') }
      it do
        # The public nonce corresponding to secnonces[0] is at index 0
        k1 = sec_nonces[0][0...64].to_i(16)
        k2 = sec_nonces[0][64...128].to_i(16)
        r1 = (Schnorr::GROUP.generator.to_jacobian * k1).to_affine
        r2 = (Schnorr::GROUP.generator.to_jacobian * k2).to_affine
        expect((r1.encode + r2.encode).unpack1('H*')).to eq(pub_nonces[0].downcase)

        # The aggregate of the first three elements of pnonce is at index 0
        agg_nonce = described_class.aggregate_nonce(pub_nonces[0..2])
        expect(agg_nonce).to eq(agg_nonces[0].downcase)
        # The aggregate of the first and fourth elements of pnonce is at index 1,
        # which is the infinity point encoded as a zeroed 33-byte array
        expect(agg_nonces[1].downcase).to eq(described_class.aggregate_nonce([pub_nonces[0], pub_nonces[3]]))

        vector['valid_test_cases'].each do |test|
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          target_pub_nonces = test['nonce_indices'].map {|i| pub_nonces[i] }
          agg_nonce = agg_nonces[test['aggnonce_index']]
          expect(described_class.aggregate_nonce(target_pub_nonces)).to eq(agg_nonce.downcase)
          msg = msgs[test['msg_index']]
          signer_index = test['signer_index']
          ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, target_pubkeys, msg)
          sec_nonce = sec_nonces[0]
          partial_sig = ctx.sign(sec_nonce, sk)
          expect(partial_sig).to eq(test['expected'].downcase)
          expect(ctx.valid_partial_sig?(partial_sig, target_pub_nonces[signer_index], signer_index))
        end
        vector['sign_error_test_cases'].each do |test|
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          agg_nonce = agg_nonces[test['aggnonce_index']]
          msg = msgs[test['msg_index']]
          sec_nonce = sec_nonces[test['secnonce_index']]
          expect {
            ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, target_pubkeys, msg)
            ctx.sign(sec_nonce, sk)
          }.to raise_error(ArgumentError)
        end
        vector['verify_fail_test_cases'].each do |test|
          sig = test['sig']
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          target_pub_nonces = test['nonce_indices'].map {|i| pub_nonces[i] }
          msg = msgs[test['msg_index']]
          signer_index = test['signer_index']
          ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, target_pubkeys, msg)
          expect(ctx.valid_partial_sig?(sig, target_pub_nonces[signer_index], signer_index)).to be false
        end
        vector['verify_error_test_cases'].each do |test|
          sig = test['sig']
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          target_pub_nonces = test['nonce_indices'].map {|i| pub_nonces[i] }
          msg = msgs[test['msg_index']]
          signer_index = test['signer_index']
          expect{
            ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, target_pubkeys, msg)
            ctx.valid_partial_sig?(sig, target_pub_nonces[signer_index], signer_index)
          }.to raise_error(ArgumentError)
        end
      end
    end

    describe 'tweak_vectors' do
      let(:vector) { read_json('tweak_vectors.json') }
      it do
        # The public key corresponding to sk is at index 0
        public_key = (Schnorr::GROUP.generator.to_jacobian * sk.to_i(16)).to_affine
        expect(pubkeys[0].downcase).to eq(public_key.encode.unpack1('H*'))
        sec_nonce = vector['secnonce']
        k1 = sec_nonce[0...64].to_i(16)
        k2 = sec_nonce[64...128].to_i(16)
        r1 = (Schnorr::GROUP.generator.to_jacobian * k1).to_affine
        r2 = (Schnorr::GROUP.generator.to_jacobian * k2).to_affine
        expect(r1.infinity?).to be false
        expect(r2.infinity?).to be false
        agg_nonce =vector['aggnonce']
        expect(described_class.aggregate_nonce(pub_nonces[0..2])).to eq(agg_nonce.downcase)
        msg = vector['msg']
        vector['valid_test_cases'].each do |test|
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          target_pub_nonces = test['nonce_indices'].map {|i| pub_nonces[i] }
          tweaks = test['tweak_indices'].map {|i| vector['tweaks'][i] }
          is_x_only = test['is_xonly']
          signer_index = test['signer_index']
          ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, target_pubkeys, msg, tweaks, is_x_only)
          expected = test['expected'].downcase
          expect(ctx.sign(sec_nonce, sk)).to eq(expected)
          expect(ctx.valid_partial_sig?(expected, target_pub_nonces[signer_index], signer_index)).to be true
        end
        vector['error_test_cases'].each do |test|
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          tweaks = test['tweak_indices'].map {|i| vector['tweaks'][i] }
          is_x_only = test['is_xonly']
          expect{
            ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, target_pubkeys, msg, tweaks, is_x_only)
            ctx.sign(sec_nonce, sk)
          }.to raise_error(ArgumentError)
        end
      end
    end

    describe 'det_sign_vectors' do
      let(:vector) { read_json('det_sign_vectors.json') }
      it do
        vector['valid_test_cases'].each do |test|
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          agg_other_nonce = test['aggothernonce']
          tweaks = test['tweaks']
          is_x_only = test['is_xonly']
          msg = msgs[test['msg_index']]
          signer_index = test['signer_index']
          rand = test['rand']
          expected = test['expected']
          pub_nonce, partial_sig = described_class.deterministic_sign(
            sk, agg_other_nonce, target_pubkeys, msg, tweaks: tweaks, modes: is_x_only, rand: rand)
          expect(pub_nonce).to eq(expected[0].downcase)
          expect(partial_sig).to eq(expected[1].downcase)
          pub_nonces = [agg_other_nonce, pub_nonce]
          agg_nonce = described_class.aggregate_nonce(pub_nonces)
          ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, target_pubkeys, msg, tweaks, is_x_only)
          expect(ctx.valid_partial_sig?(partial_sig, pub_nonce, signer_index)).to be true
        end
        vector['error_test_cases'].each do |test|
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          agg_other_nonce = test['aggothernonce']
          tweaks = test['tweaks']
          is_x_only = test['is_xonly']
          msg = msgs[test['msg_index']]
          rand = test['rand']
          expect{
            described_class.deterministic_sign(
              sk, agg_other_nonce, target_pubkeys, msg, tweaks: tweaks, modes:is_x_only, rand: rand)
          }.to raise_error(ArgumentError)
        end
      end
    end

    describe 'sig_agg_vectors' do
      let(:vector) { read_json('sig_agg_vectors.json') }
      it do
        partial_sigs = vector['psigs']
        vector['valid_test_cases'].each do |test|
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          target_pub_nonces = test['nonce_indices'].map {|i| pub_nonces[i] }
          agg_nonce = test['aggnonce']
          msg = vector['msg']
          expect(described_class.aggregate_nonce(target_pub_nonces)).to eq(agg_nonce.downcase)
          expected = test['expected']
          tweaks = test['tweak_indices'].map {|i| vector['tweaks'][i] }
          is_x_only = test['is_xonly']
          target_partial_sigs = test['psig_indices'].map {|i| partial_sigs[i] }
          ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, target_pubkeys, msg, tweaks, is_x_only)
          sig = ctx.aggregate_partial_sigs(target_partial_sigs)
          expect(sig.encode.unpack1('H*')).to eq(expected.downcase)
          agg_ctx = described_class.aggregate_with_tweaks(target_pubkeys, tweaks, is_x_only)
          expect(Schnorr.valid_sig?(msg, agg_ctx.x_only_pubkey, sig.encode)).to be true
        end
        vector['error_test_cases'].each do |test|
          target_pubkeys = test['key_indices'].map {|i| pubkeys[i] }
          msg = vector['msg']
          agg_nonce = test['aggnonce']
          tweaks = test['tweak_indices'].map {|i| vector['tweaks'][i] }
          is_x_only = test['is_xonly']
          target_partial_sigs = test['psig_indices'].map {|i| partial_sigs[i] }
          ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, target_pubkeys, msg, tweaks, is_x_only)
          expect{ctx.aggregate_partial_sigs(target_partial_sigs)}.to raise_error(ArgumentError)
        end
      end
    end
  end

  describe 'random test' do
    it do
      10.times do |i|
        sk1 = 1 + SecureRandom.random_number(Schnorr::GROUP.order - 1)
        sk2 = 1 + SecureRandom.random_number(Schnorr::GROUP.order - 1)
        pk1 = (Schnorr::GROUP.generator.to_jacobian * sk1).to_affine.encode
        pk2 = (Schnorr::GROUP.generator.to_jacobian * sk2).to_affine.encode
        sk1 = ECDSA::Format::IntegerOctetString.encode(sk1, 32)
        sk2 = ECDSA::Format::IntegerOctetString.encode(sk2, 32)
        pubkeys = [pk1, pk2]
        msg = SecureRandom.bytes(32)
        v = rand(4)
        tweaks = v.times.map { SecureRandom.bytes(32) }
        modes = v.times.map { [true, false].sample }
        agg_ctx = described_class.aggregate_with_tweaks(pubkeys, tweaks, modes)
        sec_nonce1, pub_nonce1 = described_class.gen_nonce(
          pk: pk1, sk: sk1, agg_pubkey: agg_ctx.x_only_pubkey, msg: msg, extra_in: [i].pack('N'))
        # On even iterations use regular signing algorithm for signer 2, otherwise use deterministic signing algorithm.
        if i.even?
          t = [Time.now.to_i].pack('Q>')
          sec_nonce2, pub_nonce2 = described_class.gen_nonce(
            pk: pk2, sk: sk2, agg_pubkey: agg_ctx.x_only_pubkey, msg: msg, extra_in: t)
        else
          agg_other_nonce = described_class.aggregate_nonce([pub_nonce1])
          rand = SecureRandom.bytes(32)
          pub_nonce2, sig2 = described_class.deterministic_sign(sk2, agg_other_nonce, pubkeys, msg, tweaks: tweaks, modes: modes, rand: rand)
        end
        pub_nonces = [pub_nonce1, pub_nonce2]
        agg_nonce = described_class.aggregate_nonce(pub_nonces)
        session_ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, pubkeys, msg, tweaks, modes)
        sig1 = session_ctx.sign(sec_nonce1, sk1)
        expect(session_ctx.valid_partial_sig?(sig1, pub_nonce1, 0)).to be true
        # An exception is thrown if secnonce_1 is accidentally reused
        expect{session_ctx.sign(sec_nonce1, sk1)}.to raise_error(ArgumentError)

        # Wrong signer index
        expect(session_ctx.valid_partial_sig?(sig1, pub_nonce1, 1)).to be false
        # Wrong message
        session_ctx2 = Schnorr::MuSig2::SessionContext.new(agg_nonce, pubkeys, SecureRandom.bytes(32), tweaks, modes)
        expect(session_ctx2.valid_partial_sig?(sig1, pub_nonce1, 0)).to be false

        sig2 = session_ctx.sign(sec_nonce2, sk2) if i.even?
        expect(session_ctx.valid_partial_sig?(sig2, pub_nonce2, 1)).to be true

        sig = session_ctx.aggregate_partial_sigs([sig1, sig2])
        expect(Schnorr.valid_sig?(msg, agg_ctx.x_only_pubkey, sig.encode)).to be true
      end
    end
  end

  describe 'input handling' do
    let(:sk1) { SecureRandom.bytes(32) }
    let(:sk2) { SecureRandom.bytes(32) }
    let(:pk1) { (Schnorr::GROUP.generator.to_jacobian * sk1.bti).to_affine.encode }
    let(:pk2) { (Schnorr::GROUP.generator.to_jacobian * sk2.bti).to_affine.encode }
    let(:pubkeys) { [pk1, pk2] }
    let(:msg) { SecureRandom.bytes(32) }
    let(:nonce1) { described_class.gen_nonce(pk: pk1, sk: sk1, msg: msg) }
    let(:nonce2) { described_class.gen_nonce(pk: pk2, sk: sk2, msg: msg) }
    let(:agg_nonce) { described_class.aggregate_nonce([nonce1[1], nonce2[1]]) }

    it 'sorts public keys by bytes regardless of hex letter case' do
      keys = ['03' + 'ff' * 32, '02' + 'AB' * 32, '02' + 'aa' * 32]
      expect(described_class.sort_pubkeys(keys)).to eq(['02' + 'aa' * 32, '02' + 'AB' * 32, '03' + 'ff' * 32])
    end

    it 'rejects an empty list of public keys' do
      expect { described_class.aggregate([]) }.to raise_error(ArgumentError)
    end

    it 'handles a UTF-8 message containing non-ASCII characters' do
      utf8_msg = 'こんにちは'
      n1 = described_class.gen_nonce(pk: pk1, sk: sk1, msg: utf8_msg)
      n2 = described_class.gen_nonce(pk: pk2, sk: sk2, msg: utf8_msg)
      agg = described_class.aggregate_nonce([n1[1], n2[1]])
      ctx = Schnorr::MuSig2::SessionContext.new(agg, pubkeys, utf8_msg)
      sig1 = ctx.sign(n1[0], sk1)
      sig2 = ctx.sign(n2[0], sk2)
      sig = ctx.aggregate_partial_sigs([sig1, sig2])
      agg_ctx = described_class.aggregate(pubkeys)
      expect(Schnorr.valid_sig?(utf8_msg, agg_ctx.x_only_pubkey, sig.encode)).to be true
    end

    it 'slices nonces by bytes even if the string is tagged as UTF-8' do
      binary = [agg_nonce].pack('H*')
      ctx1 = Schnorr::MuSig2::SessionContext.new(binary, pubkeys, msg)
      ctx2 = Schnorr::MuSig2::SessionContext.new(binary.dup.force_encoding('UTF-8'), pubkeys, msg)
      expect(ctx2.r).to eq(ctx1.r)
      sig1 = ctx1.sign([nonce1[0]].pack('H*').force_encoding('UTF-8'), sk1)
      expect(ctx1.valid_partial_sig?(sig1, [nonce1[1]].pack('H*').force_encoding('UTF-8'), 0)).to be true
    end

    it 'validates the length of secret inputs' do
      ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, pubkeys, msg)
      expect { ctx.sign(nonce1[0][0...-2], sk1) }.to raise_error(ArgumentError, /97 bytes/)
      expect { ctx.sign(nonce1[0], sk1[0...-1]) }.to raise_error(ArgumentError, /32 bytes/)
      other = described_class.aggregate_nonce([nonce1[1]])
      expect { described_class.deterministic_sign(sk2, other, pubkeys, msg, rand: "\x01".b) }.to raise_error(ArgumentError, /32 bytes/)
      expect { described_class.deterministic_sign(sk2[0...-1], other, pubkeys, msg) }.to raise_error(ArgumentError, /32 bytes/)
      expect { described_class.deterministic_sign(sk2, other[0...-2], pubkeys, msg) }.to raise_error(ArgumentError, /66 bytes/)
      expect { Schnorr::MuSig2::SessionContext.new(agg_nonce[0...-2], pubkeys, msg) }.to raise_error(ArgumentError, /66 bytes/)
    end

    it 'raises ArgumentError for an out-of-range signer index' do
      ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, pubkeys, msg)
      sig1 = ctx.sign(nonce1[0], sk1)
      expect { ctx.valid_partial_sig?(sig1, nonce1[1], 2) }.to raise_error(ArgumentError)
      expect { ctx.valid_partial_sig?(sig1, nonce1[1], -1) }.to raise_error(ArgumentError)
      expect { ctx.valid_partial_sig?(sig1, nonce1[1][0...-2], 0) }.to raise_error(ArgumentError)
    end

    it 'does not expose used secret nonces' do
      ctx = Schnorr::MuSig2::SessionContext.new(agg_nonce, pubkeys, msg)
      ctx.sign(nonce1[0], sk1)
      expect(ctx).not_to respond_to(:used_secnonces)
      expect(ctx.instance_variables.none? { |v| ctx.instance_variable_get(v) == [nonce1[0]].pack('H*') }).to be true
    end
  end

end
