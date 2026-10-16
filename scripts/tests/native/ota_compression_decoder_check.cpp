#include <helpers/ota/OtaLzma.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <decoder_vectors.h>

static mesh::ota::OtaLzma decoder;
static uint8_t output[8064+32];
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
  assert(decode(vector_a,8065,output,1)==Decoder::Result::Bounds);
  assert(decode(vector_a,sizeof(vector_a),output,8065)==Decoder::Result::Bounds);
  uint8_t input[96];
  for(unsigned trial=0;trial<40000;++trial) {
    const size_t size=1+nextByte()%sizeof(input),expected=1+nextByte()%128;
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
