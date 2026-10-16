#pragma once
#include <fstream>
#include <iterator>
#include <array>
#include <stdexcept>

namespace {
uint32_t compressionTestCrc32(const uint8_t* data, size_t size) {
  uint32_t crc=UINT32_MAX;
  while(size--) {
    crc^=*data++;
    for(unsigned bit=0;bit<8;++bit) crc=(crc>>1)^(0xedb88320u&(0u-(crc&1u)));
  }
  return ~crc;
}
struct CompressionFixture : LeanFixture {
  mesh::ota::OtaLeanReceiver::CompressionWorkspace workspace;
  std::vector<uint8_t> image;
  std::vector<std::vector<uint8_t>> frames;
  uint8_t canonical[59], ownerKey[32], nonce[16];
  ::ota::test::Ed25519TestSigner owner;
  static bool entropy(void*, uint8_t* out, size_t len) { std::memset(out, 0x42, len); return true; }
  static std::array<uint8_t,32> seed() { std::array<uint8_t,32> s; s.fill(1); return s; }
  CompressionFixture() : owner(seed().data()) {
    const char* path = std::getenv("OTA_COMPRESSION_FIXTURE");
    std::ifstream file(path ? path : ".tmp/compression/fixture.bin", std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), {});
    if (bytes.size() < 151 || std::memcmp(bytes.data(), "OCF1", 4))
      throw std::runtime_error("run make test-ota-compression-fixture first");
    size_t at = 4;
    std::memcpy(canonical, bytes.data()+at,59); at+=59;
    std::memcpy(ownerKey, bytes.data()+at,32); at+=32;
    if (std::memcmp(target_public_key, bytes.data()+at,32)) throw std::runtime_error("fixture target");
    at+=32; std::memcpy(nonce,bytes.data()+at,16); at+=16;
    auto size = mesh::ota::usb::getBE32(bytes.data()+at); at+=4;
    if (size > bytes.size()-at) throw std::runtime_error("fixture image");
    image.assign(bytes.begin()+at,bytes.begin()+at+size); at+=size;
    auto count = mesh::ota::usb::getBE32(bytes.data()+at); at+=4;
    while (count--) {
      if (at+2 > bytes.size()) throw std::runtime_error("fixture frame length");
      const auto len = mesh::ota::usb::getBE16(bytes.data()+at); at+=2;
      if (len > bytes.size()-at) throw std::runtime_error("fixture frame");
      frames.emplace_back(bytes.begin()+at,bytes.begin()+at+len); at+=len;
    }
    if (at != bytes.size()) throw std::runtime_error("trailing fixture");
    admins.add(ownerKey);
    integration.leanReceiver().attachCompressionWorkspace(&workspace, true);
    integration.attachEntropy(nullptr, entropy);
  }
  auto& receiver() { return integration.leanReceiver(); }
  void admit() {
    ASSERT_TRUE(integration.handleReceivedFrame(frames[0].data(), frames[0].size()));
    ASSERT_EQ(0,std::memcmp(receiver().status().beginNonce,nonce,16));
  }
  void tick(unsigned count=700) { while(count--) integration.loop(); }
  std::vector<uint8_t> resign(std::vector<uint8_t> frame, const uint8_t* target=nullptr,
                              uint32_t generation=1, const uint8_t* n=nullptr) {
    uint8_t message[256], hash[32];
    mesh::ota::computeOtaManifestHash(canonical,hash);
    auto len = mesh::ota::buildOtaCompressedMessage(target ? target : target_public_key,hash,generation,
        n ? n : nonce,frame.data(),frame.size()-64,message,sizeof(message));
    owner.sign(message,len,frame.data()+frame.size()-64);
    return frame;
  }
  void receive(const std::vector<uint8_t>& frame) {
    ASSERT_TRUE(integration.handleReceivedFrame(frame.data(),frame.size()));
    tick();
  }
};
}

TEST(LoraOtaCompression, ProductionPythonSignedFramesReachByteExactRawShaReadyAndOnlySignedCommit) {
  using namespace mesh::ota;
  CompressionFixture f;
  f.admit();
  EXPECT_EQ(usb::UsbOtaResult::TooLate,f.receiver().commit(5,nullptr));
  for(size_t i=1;i<f.frames.size();++i) f.receive(f.frames[i]);
  ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready,f.receiver().status().phase);
  std::vector<uint8_t> actual(f.image.size());
  ASSERT_TRUE(::ota::platform::isOk(f.image_region.read(0,actual.data(),actual.size())));
  EXPECT_EQ(f.image,actual);
  uint32_t floor=99; ASSERT_TRUE(f.counter.currentValue(floor)); EXPECT_EQ(0u,floor);
  uint8_t message[usb::kCommitSignedBytes],sig[64],bad[64]={};
  const auto status=f.receiver().status();
  EXPECT_EQ(usb::UsbOtaResult::Denied,f.receiver().commit(5,bad));
  usb::buildCommitSignedMessage(f.target_public_key,status.manifestHash,5,status.generation,status.beginNonce,message);
  f.owner.sign(message,sizeof(message),sig);
  ASSERT_EQ(usb::UsbOtaResult::Ok,f.receiver().commit(5,sig));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed,f.receiver().status().phase);
}

TEST(LoraOtaCompression, PartialFragmentAndPartialRawGroupSurviveReceiverRebootAndSenderReplay) {
  using namespace mesh::ota;
  CompressionFixture f; f.admit();
  const auto original=f.receiver().status();
  f.receive(f.frames[1]);
  f.receiver().restore(); f.integration.attachStagingSink(&f.guarded);
  uint16_t offset; bool complete;
  ASSERT_EQ(usb::UsbOtaResult::Ok,f.receiver().compressionProgress(0,offset,complete));
  EXPECT_EQ(0u,offset); EXPECT_FALSE(complete);
  unsigned last=1;
  while(last+1<f.frames.size() && usb::getBE16(f.frames[last+1].data()+5)==0) ++last;
  for(unsigned i=1;i<=last;++i) {
    ASSERT_TRUE(f.integration.handleReceivedFrame(f.frames[i].data(),f.frames[i].size()));
  }
  const auto writes=f.image_flash.programOpCount();
  for(unsigned ticks=0;ticks<700 && f.image_flash.programOpCount()==writes;++ticks) f.tick(1);
  f.tick(5);
  // An interrupted, fully authenticated group publishes no partial raw progress.
  ASSERT_GT(f.image_flash.programOpCount(),writes);
  ASSERT_EQ(0u,f.receiver().status().receivedBlocks);
  const auto prefix=f.receiver().status().receivedBlocks;
  f.receiver().restore(); f.integration.attachStagingSink(&f.guarded);
  EXPECT_EQ(prefix,f.receiver().status().receivedBlocks);
  EXPECT_EQ(original.generation,f.receiver().status().generation);
  EXPECT_EQ(0,std::memcmp(original.beginNonce,f.receiver().status().beginNonce,16));
  for(size_t i=1;i<f.frames.size();++i) f.receive(f.frames[i]);
  ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready,f.receiver().status().phase);
  const auto programs=f.image_flash.programOpCount();
  for(size_t i=1;i<f.frames.size();++i) f.receive(f.frames[i]);
  EXPECT_EQ(programs,f.image_flash.programOpCount());
}

TEST(LoraOtaCompression, CurrentOwnerAttemptTargetMetadataAndBoundsFailBeforeAnyFlashWrite) {
  using namespace mesh::ota;
  for(unsigned kind=0;kind<12;++kind) {
    SCOPED_TRACE(kind);
    CompressionFixture f; f.admit();
    auto frame=f.frames[1];
    if(kind==0) frame.back()^=1;
    if(kind==1) { uint8_t target[32]={9}; frame=f.resign(frame,target); }
    if(kind==2) frame=f.resign(frame,nullptr,2);
    if(kind==3) { uint8_t nonce[16]={9}; frame=f.resign(frame,nullptr,1,nonce); }
    if(kind==4) { frame[1]^=1; frame=f.resign(frame); }
    if(kind==5) { frame[15]=0xd2; frame=f.resign(frame); }
    if(kind==6) { usb::putBE16(frame.data()+7,8065); frame=f.resign(frame); }
    if(kind==7) { usb::putBE16(frame.data()+9,8065); frame=f.resign(frame); }
    if(kind==8) { usb::putBE16(frame.data()+16,1); frame=f.resign(frame); }
    if(kind==9) { usb::putBE16(frame.data()+5,65535); frame=f.resign(frame); }
    if(kind==10) { frame.resize(82); }
    if(kind==11) { f.admins.count=0; }
    const auto writes=f.image_flash.programOpCount(),metadata=f.candidate_flash.programOpCount();
    EXPECT_FALSE(f.integration.handleReceivedFrame(frame.data(),frame.size()));
    f.tick();
    EXPECT_EQ(writes,f.image_flash.programOpCount());
    EXPECT_EQ(metadata,f.candidate_flash.programOpCount());
    EXPECT_EQ(0u,f.receiver().status().receivedBlocks);
    uint32_t floor=99; ASSERT_TRUE(f.counter.currentValue(floor)); EXPECT_EQ(0u,floor);
  }
}

TEST(LoraOtaCompression, CapabilityAndProgressQueriesAreFreshBoundReadOnlyAndUseFullSmallControlGeometry) {
  using namespace mesh::ota;
  CompressionFixture f; f.admit();
  uint8_t query[kOtaCompressionPollBytes]={kOtaCompressionPollKind};
  const auto st=f.receiver().status();
  std::memcpy(query+1,f.target_public_key,32); std::memcpy(query+33,st.manifestHash,32);
  usb::putBE32(query+65,st.generation); std::memcpy(query+69,st.beginNonce,16);
  const auto writes=f.image_flash.programOpCount(),metadata=f.candidate_flash.programOpCount();
  ASSERT_TRUE(f.integration.handleReceivedFrame(query,sizeof(query),100));
  uint8_t reply[176]; size_t len;
  ASSERT_TRUE(f.integration.pollOutboundControlFrame(reply,sizeof(reply),len));
  ASSERT_EQ(kOtaCompressionReportBytes,len);
  EXPECT_EQ(kOtaLzmaThumbProfile,reply[90]); EXPECT_EQ(8064u,usb::getBE16(reply+91));
  EXPECT_EQ(writes,f.image_flash.programOpCount()); EXPECT_EQ(metadata,f.candidate_flash.programOpCount());
  query[69]^=1;
  EXPECT_FALSE(f.integration.handleReceivedFrame(query,sizeof(query),101));
}

TEST(LoraOtaCompression, ComputedCapacityFitsEveryBoundaryAndConsumesAllAvailableStockTxRxSpace) {
  using namespace mesh::ota;
  for(unsigned width=1;width<=3;++width) for(unsigned hops=0;hops<=63;++hops)
    for(bool retry:{false,true}) for(bool codes:{false,true}) {
      const auto capacity=otaCompressedFragmentCapacity(width,hops,retry,codes);
      if(width*hops>64) { EXPECT_EQ(0u,capacity); continue; }
      const auto raw=2+width*hops+4*codes+5*retry+kOtaCompressionFragmentOverhead+capacity;
      EXPECT_LE(raw+2,176u); EXPECT_EQ(raw+3,176u);
      EXPECT_GT(raw+1+3,176u);
    }
  EXPECT_EQ(89u,otaCompressedFragmentCapacity(1,0,false));
  EXPECT_EQ(83u,otaCompressedFragmentCapacity(1,1,true));
  EXPECT_EQ(81u,otaCompressedFragmentCapacity(3,1,true));
}

TEST(LoraOtaCompression, PortableReceiverRejectsThumbAndMixedNonzeroOffsetGroupsBeforeDecode) {
  using namespace mesh::ota;
  CompressionFixture f; f.admit();
  std::vector<uint8_t> first, second;
  for (const auto& frame : f.frames) if (frame[0] == kOtaCompressedFragmentKind &&
      usb::getBE16(frame.data()+5) == 1) {
    if (first.empty()) first = frame;
    else { second = frame; break; }
  }
  ASSERT_FALSE(second.empty());
  f.receiver().attachCompressionWorkspace(&f.workspace, false);
  EXPECT_EQ(usb::UsbOtaResult::BadRequest,f.receiver().handleCompressedFragment(first.data(),first.size()));
  f.receiver().attachCompressionWorkspace(&f.workspace, true);
  ASSERT_EQ(usb::UsbOtaResult::Ok,f.receiver().handleCompressedFragment(first.data(),first.size()));
  usb::putBE16(second.data()+5,2); second=f.resign(second);
  EXPECT_EQ(usb::UsbOtaResult::Mismatch,f.receiver().handleCompressedFragment(second.data(),second.size()));
  f.tick();
  EXPECT_EQ(0u,f.receiver().status().receivedBlocks);
  EXPECT_EQ(0u,f.workspace.diagnostics.slices);
}

TEST(LoraOtaCompression, RealReliableAndRepairWrappersCarryOwnerSignedCompressedFramesToReady) {
  using namespace mesh::ota;
  CompressionFixture f; f.admit();
  uint32_t attempt=1;
  for (size_t i=1;i<f.frames.size();++i) {
    uint8_t packet[176];
    const auto length=encodeOtaRetryAttempt(attempt++,f.frames[i].data(),f.frames[i].size(),
                                           packet,sizeof(packet),(i%2)==0);
    ASSERT_EQ(f.frames[i].size()+5,length);
    ASSERT_TRUE(f.integration.handleReceivedFrame(packet,length));
    f.tick();
  }
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready,f.receiver().status().phase);
}

TEST(LoraOtaCompression, RevokedOwnerCannotDecodeOrProgramAnAlreadyBufferedGroup) {
  using namespace mesh::ota;
  for (bool after_decode : {false,true}) {
    CompressionFixture f; f.admit();
    for (size_t i=1;i<f.frames.size() && usb::getBE16(f.frames[i].data()+5)==0;++i)
      ASSERT_TRUE(f.integration.handleReceivedFrame(f.frames[i].data(),f.frames[i].size()));
    if (after_decode) {
      for (unsigned ticks=0;ticks<700 && (!f.workspace.verified || f.workspace.preflight);++ticks) f.tick(1);
      ASSERT_TRUE(f.workspace.verified);
      ASSERT_FALSE(f.workspace.preflight);
    }
    const auto programs=f.image_flash.programOpCount();
    f.admins.count=0; f.tick();
    EXPECT_EQ(programs,f.image_flash.programOpCount());
    EXPECT_EQ(0u,f.receiver().status().receivedBlocks);
    EXPECT_EQ(usb::UsbOtaResult::Denied,f.receiver().lastCompressionWriteResult());
  }
}

TEST(LoraOtaCompression, SignedTruncatedTrailingAndWrongFilterGroupsNeverReachFlash) {
  using namespace mesh::ota;
  for (unsigned kind=0;kind<3;++kind) {
    CompressionFixture f; f.admit();
    std::vector<uint8_t> header, stored;
    for (const auto& frame : f.frames) if (frame[0] == kOtaCompressedFragmentKind &&
        usb::getBE16(frame.data()+5) == 1) {
      if (header.empty()) header.assign(frame.begin(),frame.begin()+18);
      stored.insert(stored.end(),frame.begin()+18,frame.end()-64);
    }
    ASSERT_FALSE(stored.empty());
    ASSERT_EQ(kOtaLzmaThumbProfile,header[15]);
    if (kind==0) stored.pop_back();
    if (kind==1) stored.push_back(0);
    if (kind==2) header[15]=kOtaLzmaProfile;
    usb::putBE16(header.data()+7,stored.size());
    const auto programs=f.image_flash.programOpCount();
    for (size_t at=0;at<stored.size();at+=83) {
      auto frame=header;
      usb::putBE16(frame.data()+16,at);
      const size_t take=std::min(size_t(83),stored.size()-at);
      frame.insert(frame.end(),stored.begin()+at,stored.begin()+at+take);
      frame.resize(frame.size()+64); frame=f.resign(frame);
      ASSERT_TRUE(f.integration.handleReceivedFrame(frame.data(),frame.size()));
    }
    f.tick();
    EXPECT_EQ(programs,f.image_flash.programOpCount());
    EXPECT_EQ(0u,f.receiver().status().receivedBlocks);
    EXPECT_TRUE(f.receiver().lastCompressionDecodeResult()!=OtaLzma::Result::Ok ||
                f.receiver().lastCompressionWriteResult()!=usb::UsbOtaResult::Ok);
    uint32_t floor=99; ASSERT_TRUE(f.counter.currentValue(floor)); EXPECT_EQ(0u,floor);
  }
}

TEST(LoraOtaCompression, RuntimeDiagnosticsAreReadOnlyBoundedAndDoNotRedecodeCompletedDuplicates) {
  using namespace mesh::ota;
  CompressionFixture f;
  struct Probe {
    uint32_t clock=0;
    static void sample(void* ctx,uint32_t& us,uint32_t& heap,uint32_t& stack) {
      auto& value=*static_cast<Probe*>(ctx);
      us=value.clock; value.clock+=7; heap=10000; stack=2000;
    }
  } probe;
  f.receiver().setCompressionRuntimeProbe(&probe,Probe::sample);
  const auto programs=f.image_flash.programOpCount(), metadata=f.candidate_flash.programOpCount();
  char text[160];
  formatOtaCodec(text,sizeof(text),f.receiver());
  EXPECT_NE(nullptr,std::strstr(text,"codec=lzma1-g8064 thumb=1 measured=1 groups=0"));
  EXPECT_EQ(programs,f.image_flash.programOpCount()); EXPECT_EQ(metadata,f.candidate_flash.programOpCount());
  EXPECT_FALSE(f.workspace.diagnostics.measured);
  char tiny[8]; formatOtaCodec(tiny,sizeof(tiny),f.receiver()); EXPECT_EQ("Err - c",std::string(tiny));
  f.admit();
  size_t last=1;
  while (last+1<f.frames.size() && usb::getBE16(f.frames[last+1].data()+5)==0) ++last;
  for (size_t i=1;i<=last;++i) f.receive(f.frames[i]);
  auto stats=f.receiver().compressionDiagnostics();
  EXPECT_TRUE(stats.measured); EXPECT_EQ(1u,stats.groups);
  EXPECT_EQ(7u,stats.maxSliceUs); EXPECT_EQ(7u*stats.slices,stats.maxGroupUs);
  EXPECT_EQ(10000u,stats.minFreeHeap); EXPECT_EQ(2000u,stats.minFreeStack);
  f.receive(f.frames[last]);
  EXPECT_EQ(stats.slices,f.receiver().compressionDiagnostics().slices);
  EXPECT_EQ(stats.groups,f.receiver().compressionDiagnostics().groups);
  formatOtaCodec(text,sizeof(text),f.receiver()); EXPECT_NE(nullptr,std::strstr(text,"heap=10000 stack=2000"));
}

TEST(LoraOtaCompression, BitmapPublicationStartsAfterWholeProgramAndInterruptedPublicationIsMonotonic) {
  using namespace mesh::ota;
  CompressionFixture f; f.admit();
  for (size_t i=1;i<f.frames.size() && usb::getBE16(f.frames[i].data()+5)==0;++i)
    ASSERT_TRUE(f.integration.handleReceivedFrame(f.frames[i].data(),f.frames[i].size()));
  for (unsigned n=0;n<700 && !f.receiver().status().receivedBlocks;++n) f.tick(1);
  ASSERT_EQ(1u,f.receiver().status().receivedBlocks);
  std::vector<uint8_t> raw(8064);
  ASSERT_TRUE(::ota::platform::isOk(f.image_region.read(0,raw.data(),raw.size())));
  EXPECT_TRUE(std::equal(raw.begin(),raw.end(),f.image.begin()));
  const auto programs=f.image_flash.programOpCount();
  f.receiver().restore(); f.integration.attachStagingSink(&f.guarded);
  EXPECT_EQ(1u,f.receiver().status().receivedBlocks);
  for (size_t i=1;i<f.frames.size() && usb::getBE16(f.frames[i].data()+5)==0;++i) f.receive(f.frames[i]);
  EXPECT_EQ(96u,f.receiver().status().receivedBlocks);
  // The missing bitmap prefix does not cause another candidate BEGIN or erase.
  EXPECT_GE(f.image_flash.programOpCount(),programs);
  EXPECT_EQ(1u,f.receiver().status().generation);
}

    TEST(LoraOtaCompression, TornProgramReplaysRawBytesIdempotentlyWithoutResettingBitmapOrBegin) {
      using namespace mesh::ota;
      using Flash=::ota::test::FakeNorFlash;
      for(auto timing:{Flash::InjectionTiming::Before,Flash::InjectionTiming::Mid,Flash::InjectionTiming::After}) {
        CompressionFixture f; f.admit();
        Flash::FaultSpec fault;
        fault.kind=Flash::OpKind::Program; fault.timing=timing; fault.partial_bytes=7;
        fault.trigger_op_count=f.image_flash.programOpCount()+3;
        f.image_flash.armFault(fault);
        unsigned last=1;
        while(last+1<f.frames.size() && usb::getBE16(f.frames[last+1].data()+5)==0) ++last;
        for(unsigned i=1;i<=last;++i) ASSERT_TRUE(f.integration.handleReceivedFrame(f.frames[i].data(),f.frames[i].size()));
        f.tick();
        ASSERT_EQ(usb::UsbOtaResult::IoError,f.receiver().lastCompressionWriteResult());
        const auto partial=f.receiver().status();
        ASSERT_EQ(0u,partial.receivedBlocks);
        f.image_flash.clearFault(); f.receiver().restore(); f.integration.attachStagingSink(&f.guarded);
        EXPECT_EQ(partial.receivedBlocks,f.receiver().status().receivedBlocks);
        for(size_t i=1;i<f.frames.size();++i) f.receive(f.frames[i]);
        EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready,f.receiver().status().phase);
        EXPECT_EQ(partial.generation,f.receiver().status().generation);
        EXPECT_EQ(0,std::memcmp(partial.beginNonce,f.receiver().status().beginNonce,16));
      }
    }

    TEST(LoraOtaCompression, BadCodecOrCrcAndConflictingDuplicateNeverProgramUnvalidatedBytes) {
      using namespace mesh::ota;
      for(unsigned kind=0;kind<4;++kind) {
        CompressionFixture f; f.admit();
        const auto writes=f.image_flash.programOpCount();
        if(kind<2) {
          auto frame=f.frames[1]; frame.resize(83);
          usb::putBE16(frame.data()+7,1); frame[15]=kOtaLzmaProfile;
          frame[18]=kind==0?0x07:0x03; frame=f.resign(frame);
          EXPECT_TRUE(f.integration.handleReceivedFrame(frame.data(),frame.size()));
        } else if(kind==2) {
          for(size_t i=1;i<f.frames.size() && usb::getBE16(f.frames[i].data()+5)==0;++i) {
            auto frame=f.frames[i]; frame[11]^=1; frame=f.resign(frame);
            EXPECT_TRUE(f.integration.handleReceivedFrame(frame.data(),frame.size()));
          }
        } else {
          f.receive(f.frames[1]);
          auto frame=f.frames[1]; frame[18]^=1; frame=f.resign(frame);
          EXPECT_FALSE(f.integration.handleReceivedFrame(frame.data(),frame.size()));
        }
        f.tick(); EXPECT_EQ(writes,f.image_flash.programOpCount());
        EXPECT_EQ(0u,f.receiver().status().receivedBlocks);
      }
    }

    TEST(LoraOtaCompression, AuthenticatedWrongRawImageFailsFinalManifestHashAndCannotCommitOrAdvanceFloor) {
      using namespace mesh::ota;
      CompressionFixture f; f.admit();
      auto wrong=f.image; wrong[0]^=1;
      const uint32_t crc=compressionTestCrc32(wrong.data(),8064);
      for(size_t i=1;i<f.frames.size();++i) {
        auto frame=f.frames[i];
        if(usb::getBE16(frame.data()+5)==0) {
          usb::putBE32(frame.data()+11,crc);
          if(usb::getBE16(frame.data()+16)==0) frame[18]^=1;
          frame=f.resign(frame);
        }
        f.receive(frame);
      }
      EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Failed,f.receiver().status().phase);
      uint8_t signature[64]={};
      EXPECT_EQ(usb::UsbOtaResult::TooLate,f.receiver().commit(5,signature));
      uint32_t floor=99; ASSERT_TRUE(f.counter.currentValue(floor)); EXPECT_EQ(0u,floor);
    }
