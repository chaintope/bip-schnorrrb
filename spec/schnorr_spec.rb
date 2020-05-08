require 'spec_helper'
require 'csv'

RSpec.describe Schnorr do

  let(:vectors) {read_csv('test-vectors.csv')}

  it "has a version number" do
    expect(Schnorr::VERSION).not_to be nil
  end

  # https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
  describe 'Test Vector' do
    it 'should be passed.' do
      vectors.each do |v|
        priv_key = v['secret key'] ? [v['secret key']].pack('H*') : nil
        pubkey = [v['public key']].pack('H*')
        message = [v['message']].pack('H*')
        expected_sig = v['signature']
        result = v['verification result'] == 'TRUE'
        aux_rand = [v['aux_rand']].pack("H*")
        if priv_key
          signature = Schnorr.sign(message, priv_key, aux_rand)
          expect(signature.encode.unpack('H*').first.upcase).to eq(expected_sig)
        end
        expect(Schnorr.valid_sig?(message, pubkey, [expected_sig].pack('H*'))).to be result
      end
    end
  end

end
