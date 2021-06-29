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
          expect(signature.encode.unpack1('H*').upcase).to eq(expected_sig)
        end
        expect(Schnorr.valid_sig?(message, pubkey, [expected_sig].pack('H*'))).to be result
      end
    end
  end

  context 'aux rand not provided' do
    it 'create nonce without aux rand' do
      message = ['d68ed1f688dacf05b14373b0bda0187b27c79a4ba08a2770e5a7684f54ed42ad'].pack('H*')
      priv_key = ['ecdbab5619c5f7d6feefe5b430869e4590f1ab31b158bbb47c90fc9b370051c6'].pack('H*')
      signature = Schnorr.sign(message, priv_key)
      expect(signature.encode.unpack1('H*')).to eq('cb6554f93b3d4ad0f8c940d317a29cda93bdd8cde62de32a3fe64f2f6ef2d8c56469ec1f5d24e28f98b8dbf871b7fbc8dc3e72d80ac69b694ae87489053a19c7')
    end
  end

end
