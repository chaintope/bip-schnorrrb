# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'ec_point_ext' do
  describe 'ECDSA::Point' do
    describe '#encode' do
      subject do
        ECDSA::Point.new(ECDSA::Group::Secp256k1, 0xb11ef5967189735717be555cd51e941888214ac20035a22e86b1d5084a20f648, 0x1c8d38549d4c5b10a81bcf05a621d4175f43b502587a1018ad9fcd56a5d6b699)
      end
      context 'only x' do
        it 'should return binary string which has only X-coordinate.' do
          expect(subject.encode(true).unpack1('H*')).to eq('b11ef5967189735717be555cd51e941888214ac20035a22e86b1d5084a20f648')
        end
      end

      context 'not only x' do
        it 'should return binary string with compressed key.' do
          expect(subject.encode.unpack1('H*')).to eq('03b11ef5967189735717be555cd51e941888214ac20035a22e86b1d5084a20f648')
        end
      end
    end
  end

  describe 'ECDSA::Format::PointOctetString' do
    describe '#decode' do
      it 'should return ECDSA::Point.' do
        uncompressed = '044ce60301a2aefd40b09a8709b99381260fa61fdb4ee0f0c54f15aca9c1966373ce5db298eaa66e9ac0401ccda0be88917cd816b9e0768a9f63adf5e8a07f9c3a'
        result = ECDSA::Format::PointOctetString.decode([uncompressed].pack('H*'), ECDSA::Group::Secp256k1)
        expect(result.x).to eq(0x4ce60301a2aefd40b09a8709b99381260fa61fdb4ee0f0c54f15aca9c1966373)
        expect(result.y).to eq(0xce5db298eaa66e9ac0401ccda0be88917cd816b9e0768a9f63adf5e8a07f9c3a)

        compressed = '0202ff96ff72f99294ab1d9e659c86f605b2d9343e50e0b3c4a896fae40d625c62'
        result = ECDSA::Format::PointOctetString.decode([compressed].pack('H*'), ECDSA::Group::Secp256k1)
        expect(result.x).to eq(0x2ff96ff72f99294ab1d9e659c86f605b2d9343e50e0b3c4a896fae40d625c62)
        expect(result.y).to eq(0xdebc79ffc6e47ed1e122fb4d617cbe37544e3cc566154543475931a118696be2)

        xonly = '02ff96ff72f99294ab1d9e659c86f605b2d9343e50e0b3c4a896fae40d625c62'
        result = ECDSA::Format::PointOctetString.decode([xonly].pack('H*'), ECDSA::Group::Secp256k1)
        expect(result.x).to eq(0x2ff96ff72f99294ab1d9e659c86f605b2d9343e50e0b3c4a896fae40d625c62)
        expect(result.y).to eq(0xdebc79ffc6e47ed1e122fb4d617cbe37544e3cc566154543475931a118696be2)

        xonly = '04508b2724ad57b29a41f731dfc5e861f2edb721555c0de1ba47d6b92fbb0ccc'
        result = ECDSA::Format::PointOctetString.decode([xonly].pack('H*'), ECDSA::Group::Secp256k1)
        expect(result.x).to eq(0x4508b2724ad57b29a41f731dfc5e861f2edb721555c0de1ba47d6b92fbb0ccc)
        expect(result.y).to eq(0x27bac8efb88a5e647d65fdba5adeab06f8cfaa76e3b949ad22748868fc390350)
      end
    end
  end
end
