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
        private_key = (Schnorr::GROUP.generator.to_jacobian * sk.to_i(16)).to_affine
        expect(pubkeys[0].downcase).to eq(private_key.encode.unpack1('H*'))
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

end