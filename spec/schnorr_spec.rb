require 'spec_helper'
require 'csv'

RSpec.describe Schnorr do

  let(:vectors) { read_csv('test-vectors.csv') }

  # https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
  describe 'Test Vector' do
    it 'should be passed.' do
      vectors.each do |v|
        priv_key = v['secret key'] ? [v['secret key']].pack('H*') : nil
        pubkey = [v['public key']].pack('H*')
        message = [v['message']].pack('H*')
        expected_sig = v['signature']
        result = v['verification result'] == 'TRUE'
        aux_rand = [v['aux_rand']].pack('H*')
        if priv_key
          signature = Schnorr.sign(message, priv_key, aux_rand)
          expect(Schnorr.sign(message, v['secret key'], v['aux_rand'])).to eq(signature)
          expect(signature.encode.unpack1('H*').upcase).to eq(expected_sig)
        end
        expect(Schnorr.valid_sig?(message, pubkey, [expected_sig].pack('H*'))).to be result
        expect(Schnorr.valid_sig?(message, v['public key'], [expected_sig].pack('H*'))).to be result
      end
    end
  end

  context 'aux rand not provided' do
    it 'create nonce without aux rand' do
      message = ['d68ed1f688dacf05b14373b0bda0187b27c79a4ba08a2770e5a7684f54ed42ad'].pack('H*')
      priv_key = ['ecdbab5619c5f7d6feefe5b430869e4590f1ab31b158bbb47c90fc9b370051c6'].pack('H*')
      signature = Schnorr.sign(message, priv_key)
      expect(signature.encode.unpack1('H*')).to eq('9cbba40f90595e0ea05484725eeeb3fcd421ea6b98189c5c92d30869d4093d2736f6f90310b44e6dc4f0c2b47c7326f76ba7f340f28b0370d5962ef17c9247c9')
    end
  end

end
