require 'spec_helper'

RSpec.describe 'ec_point_ext' do

  describe 'ECDSA::Point' do

    describe '#encode' do
      subject {
        ECDSA::Point.new(ECDSA::Group::Secp256k1, 0xb11ef5967189735717be555cd51e941888214ac20035a22e86b1d5084a20f648, 0x1c8d38549d4c5b10a81bcf05a621d4175f43b502587a1018ad9fcd56a5d6b699)
      }
      context 'only x' do
        it 'should return binary string which has only X-coordinate.' do
          expect(subject.encode(true).unpack('H*').first).to eq('b11ef5967189735717be555cd51e941888214ac20035a22e86b1d5084a20f648')
        end
      end

      context 'not only x' do
        it 'should return binary string with compressed key.' do
          expect(subject.encode.unpack('H*').first).to eq('03b11ef5967189735717be555cd51e941888214ac20035a22e86b1d5084a20f648')
        end
      end
    end

  end

end