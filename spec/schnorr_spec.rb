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
    let(:message) { ['d68ed1f688dacf05b14373b0bda0187b27c79a4ba08a2770e5a7684f54ed42ad'].pack('H*') }
    let(:priv_key) { ['ecdbab5619c5f7d6feefe5b430869e4590f1ab31b158bbb47c90fc9b370051c6'].pack('H*') }
    let(:pubkey) { (Schnorr::GROUP.generator.to_jacobian * priv_key.bti).to_affine.encode(true) }

    it 'create nonce without aux rand' do
      signature = Schnorr.sign(message, priv_key)
      expect(signature.encode.unpack1('H*')).to eq('9cbba40f90595e0ea05484725eeeb3fcd421ea6b98189c5c92d30869d4093d2736f6f90310b44e6dc4f0c2b47c7326f76ba7f340f28b0370d5962ef17c9247c9')
      expect(Schnorr.sign(message, priv_key, Schnorr::DEFAULT_AUX)).to eq(signature)
      expect(Schnorr.valid_sig?(message, pubkey, signature.encode)).to be true
    end
  end

  describe 'input handling' do
    let(:priv_key) { ['ecdbab5619c5f7d6feefe5b430869e4590f1ab31b158bbb47c90fc9b370051c6'].pack('H*') }
    let(:pubkey) { (Schnorr::GROUP.generator.to_jacobian * priv_key.bti).to_affine.encode(true) }

    it 'signs and verifies a UTF-8 message containing non-ASCII characters' do
      message = 'こんにちは'
      signature = Schnorr.sign(message, priv_key)
      expect(Schnorr.valid_sig?(message, pubkey, signature.encode)).to be true
      expect(Schnorr.valid_sig?(message.b, pubkey, signature.encode)).to be true
    end

    it 'treats a hex message the same in signing and verification' do
      hex = '5e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c'
      signature = Schnorr.sign(hex, priv_key)
      expect(signature).to eq(Schnorr.sign([hex].pack('H*'), priv_key))
      expect(Schnorr.valid_sig?(hex, pubkey, signature.encode)).to be true
      expect(Schnorr.valid_sig?([hex].pack('H*'), pubkey, signature.encode)).to be true
    end

    it 'decodes a signature by bytes even if the string is tagged as UTF-8' do
      # 64 bytes which form 32 two-byte UTF-8 characters when tagged as UTF-8.
      bytes = ("\xC3\xA9".b * 32)
      expect(Schnorr::Signature.decode(bytes.dup.force_encoding('UTF-8'))).to eq(Schnorr::Signature.decode(bytes))
      signature = Schnorr.sign(SecureRandom.bytes(32), priv_key)
      expect(Schnorr::Signature.decode(signature.encode.dup.force_encoding('UTF-8'))).to eq(signature)
    end

    it 'raises ArgumentError for an invalid private key or aux_rand' do
      message = SecureRandom.bytes(32)
      expect { Schnorr.sign(message, "\x00".b * 32) }.to raise_error(ArgumentError)
      expect { Schnorr.sign(message, priv_key, "\x00".b * 31) }.to raise_error(ArgumentError)
    end

    it 'raises InvalidSignatureError for a public key that is not on the curve' do
      message = SecureRandom.bytes(32)
      signature = Schnorr.sign(message, priv_key)
      expect { Schnorr.check_sig!(message, "\x05".b * 32, signature.encode) }.to raise_error(Schnorr::InvalidSignatureError)
      expect(Schnorr.valid_sig?(message, "\x05".b * 32, signature.encode)).to be false
    end
  end

end

