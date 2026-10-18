#include <helpers/ota/OtaLzma.h>
#include <cassert>
#include <cstdio>
#include <cstring>

static constexpr uint8_t vector_a[] = {
  0x00,0x20,0xc1,0xfb,0xff,0xff,0xff,0xe0,0x00,0x00,0x00
};
static constexpr uint8_t vector_aa[] = {
  0x00,0x20,0x90,0x5d,0xf7,0xff,0xff,0xff,0xf0,0x80,0x00,0x00
};
static constexpr uint8_t vector_8192_zero[] = {
  0x00,0x00,0x6f,0xfd,0xff,0xff,0xa3,0xb7,0xff,0x44,0x1f,0x9a,0xf8,0xf3,
  0x8b,0x46,0x5f,0xcd,0x86,0x2b,0x4e,0xcd,0xd2,0xd4,0xf1,0x20,0xb4,0x30,
  0x28,0xd9,0xb4,0xfd,0x10,0x27,0x23,0xeb,0x7e,0xcf,0x7f,0xff,0xff,0xd8,
  0x38,0x00,0x00
};

static mesh::ota::OtaLzma decoder;
static uint8_t output[mesh::ota::OtaLzma::kMaxOutput + 32];
static uint32_t rng=0x12345678;
static uint8_t nextByte() { rng^=rng<<13; rng^=rng>>17; rng^=rng<<5; return rng; }

int main() {
  using Decoder=mesh::ota::OtaLzma;
  auto decode=[](const uint8_t* in,size_t size,uint8_t* out,size_t expected) {
    auto result=decoder.begin(in,size,out,expected);
    while(result==Decoder::Result::Pending) {
      const auto before=decoder.produced(),consumed=decoder.consumed();
      result=decoder.step();
      assert(decoder.produced()-before<=Decoder::kSliceBytes);
      assert(decoder.consumed()-consumed<=Decoder::kSliceBytes);
      assert(decoder.slices()<=Decoder::kMaxSlices);
    }
    return result;
  };
  uint8_t trailing[sizeof(vector_a)+1];
  std::memcpy(trailing,vector_a,sizeof(vector_a)); trailing[sizeof(vector_a)]=0;
  assert(decode(vector_a,sizeof(vector_a),output,1)==Decoder::Result::Ok && output[0]=='A');
  assert(decode(vector_a,sizeof(vector_a)-1,output,1)!=Decoder::Result::Ok);
  assert(decode(vector_a,sizeof(vector_a),output,2)==Decoder::Result::OutputLength);
  assert(decode(trailing,sizeof(trailing),output,1)==Decoder::Result::Trailing);
  output[1]=0xa5;
  assert(decode(vector_aa,sizeof(vector_aa),output,1)!=Decoder::Result::Ok && output[1]==0xa5);
  assert(decode(vector_a,Decoder::kMaxOutput+1,output,1)==Decoder::Result::Bounds);
  assert(decode(vector_a,sizeof(vector_a),output,Decoder::kMaxOutput+1)==Decoder::Result::Bounds);
  std::memset(output,0xa5,sizeof(output));
  assert(decode(vector_8192_zero,sizeof(vector_8192_zero),output+16,
                Decoder::kMaxOutput)==Decoder::Result::Ok);
  for(size_t i=0;i<Decoder::kMaxOutput;++i) assert(output[16+i]==0);
  for(unsigned i=0;i<16;++i) {
    assert(output[i]==0xa5); assert(output[16+Decoder::kMaxOutput+i]==0xa5);
  }
  uint8_t input[96];
  for(unsigned trial=0;trial<40000;++trial) {
    const size_t size=1+nextByte()%sizeof(input);
    const size_t expected=trial%16 ? 1+nextByte()%128 :
        1+((static_cast<size_t>(nextByte())<<8)|nextByte())%Decoder::kMaxOutput;
    for(size_t i=0;i<size;++i) input[i]=nextByte();
    std::memset(output,0xa5,sizeof(output));
    if(trial&1) input[0]=0;
    decode(input,size,output+16,expected);
    for(unsigned i=0;i<16;++i) {
      assert(output[i]==0xa5); assert(output[16+expected+i]==0xa5);
    }
  }
  std::puts("PASS: persistent no-heap LZMA decoder, 128-byte input/output slices, exact/truncated/trailing/overexpansion checks, 40000 malformed canary trials");
}
