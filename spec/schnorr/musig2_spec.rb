require 'spec_helper'

RSpec.describe Schnorr::MuSig2 do

  describe 'Test Vector' do
    describe 'key_sort_vectors' do
      it do
        vector = read_json('key_sort_vectors.json')
        sorted_keys = described_class.sort_pubkeys(vector['pubkeys'])
        expect(sorted_keys).to eq(vector['sorted_pubkeys'])
      end
    end

    describe 'key_agg_vectors' do
      let(:vector) {  read_json('key_agg_vectors.json') }

      context 'Valid case' do
        it do
          vector['valid_test_cases'].each do |keys|
            pubkey_candidates = keys['key_indices'].map{|i|vector['pubkeys'][i]}
            agg_key_ctx = described_class.aggregate(pubkey_candidates)
            expect(agg_key_ctx.x_only_pubkey).to eq(keys['expected'].downcase)
          end
        end
      end

      context 'Error case' do
        it do
          tweaks = vector['tweaks']
          vector['error_test_cases'].each do |error|
            pubkey_candidates = error['key_indices'].map{|i| vector['pubkeys'][i] }
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
      it do
        vector = read_json('nonce_gen_vectors.json')
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
      it do
        vector = read_json('nonce_agg_vectors.json')
        pub_nonces = vector['pnonces']
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
  end

end