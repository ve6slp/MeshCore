// Linux maps the nRF read-only address space so the production running reader,
// boot-marker reader and health accessor execute without test replacements.
#include <helpers/ota/OtaBoardBackendCommon.h>
#include <helpers/ota/OtaV4Receiver.h>
#include <ota/trust/Ed25519SignatureVerifier.h>
#include "../../../test/test_lora_ota_storage/FakeNorFlash.h"
#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <sys/mman.h>
#include <sys/random.h>

using namespace mesh::ota::v4;
using Bytes = std::vector<uint8_t>;
using Region = ::ota::platform::FlashRegion;

static Bytes unhex(const std::string& text) {
  assert(text.size() % 2 == 0);
  Bytes bytes;
  for (size_t i = 0; i < text.size(); i += 2) {
    auto digit = [](char c) {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      assert(false); return 0;
    };
    bytes.push_back(uint8_t(digit(text[i]) * 16 + digit(text[i + 1])));
  }
  return bytes;
}

static Bytes load(const std::string& path, size_t size) {
  std::ifstream file(path, std::ios::binary);
  Bytes bytes(size);
  assert(file.read(reinterpret_cast<char*>(bytes.data()), size));
  assert(file.peek() == std::char_traits<char>::eof());
  return bytes;
}

static void save(const std::string& path, const uint8_t* bytes, size_t size) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  assert(file.write(reinterpret_cast<const char*>(bytes), size));
  file.close();
  assert(file);
}

struct Keys {
  uint8_t identity[32], secret[64], admin[32];
  static Result identityHook(void* context, uint8_t out[32]) {
    std::memcpy(out, static_cast<Keys*>(context)->identity, 32);
    return Result::Ok;
  }
  static bool adminHook(void* context, const uint8_t key[32]) {
    return !std::memcmp(key, static_cast<Keys*>(context)->admin, 32);
  }
  static Result signHook(void* context, const char* domain, size_t domainSize,
                         const uint8_t* bytes, size_t size, uint8_t signature[64]) {
    auto& self = *static_cast<Keys*>(context);
    Bytes message;
    if (domainSize) message.insert(message.end(), domain, domain + domainSize);
    message.insert(message.end(), bytes, bytes + size);
    ::ota::trust::ed25519_impl::ed25519_sign(signature, message.data(), message.size(),
                                           self.identity, self.secret);
    return Result::Ok;
  }
};

static bool entropy(uint8_t* bytes, size_t size) {
  return getrandom(bytes, size, 0) == static_cast<ssize_t>(size);
}

int main(int argc, char** argv) {
  assert(argc == 6);
  const std::string directory = argv[1];
  const Bytes admin = unhex(argv[2]), seed = unhex(argv[3]);
  assert(admin.size() == 32 && seed.size() == 32);
  Keys keys;
  std::memcpy(keys.admin, admin.data(), 32);
  ::ota::trust::ed25519_impl::ed25519_create_keypair(keys.identity, keys.secret, seed.data());
  Policy policy;
  const uint32_t target = std::stoul(argv[4], nullptr, 0);
  policy.boardFamily = target >> 16; policy.boardVariant = target & 65535;
  policy.role = std::stoul(argv[5]);
  policy.appAddress = OTA_NRF52_INTERNAL_IMAGE_OFFSET;
  policy.maxImageBytes = OTA_NRF52_INTERNAL_IMAGE_SIZE;
  policy.bootloaderCapabilities = 1;

  constexpr uintptr_t mappedStart = OTA_NRF52_INTERNAL_IMAGE_OFFSET;
  constexpr size_t mappedSize = 0x100000 - mappedStart;
  void* mapped = mmap(reinterpret_cast<void*>(mappedStart), mappedSize,
                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  assert(mapped == reinterpret_cast<void*>(mappedStart));
  auto internal = load(directory + "/internal.bin", 0x100000);
  std::memcpy(mapped, internal.data() + mappedStart, mappedSize);
  assert(mprotect(mapped, mappedSize, PROT_READ) == 0);
  ::ota::test::FakeNorFlash flash(OTA_NRF52_QSPI_TOTAL_BYTES, OTA_NRF52_QSPI_ERASE_UNIT_BYTES);
  const Bytes qspi = load(directory + "/qspi.bin", flash.rawSize());
  assert(::ota::platform::isOk(flash.program(0, qspi.data(), qspi.size())));
  Region payload(flash, OTA_NRF52_CANDIDATE_OFFSET, OTA_NRF52_INTERNAL_IMAGE_SIZE);
  Region metadata(flash, OTA_NRF52_CANDIDATE_RECORD_OFFSET, OTA_NRF52_CANDIDATE_RECORD_SIZE);
  Region commands(flash, 0x18c000, 8192), state(flash, 0x18e000, 8192);
  Region confirm(flash, 0x190000, 8192), floor(flash, 0x192000, 8192);
  ::ota::trust::Ed25519SignatureVerifier signatures;
  NrfRunningReader running;
  NrfFirmwarePlatform platform(policy, payload, metadata, commands, state, floor, confirm,
                               signatures, running, entropy);
  RuntimeHooks hooks;
  hooks.context = &keys; hooks.identity = Keys::identityHook;
  hooks.isCurrentAdmin = Keys::adminHook; hooks.sign = Keys::signHook;
  platform.attach(hooks);
  platform.installationReady();
  Receiver receiver(platform);
  assert(receiver.begin() == Result::Ok);
  auto flush = [&] {
    save(directory + "/qspi.bin", flash.rawBuffer(), flash.rawSize());
    save(directory + "/internal.bin", internal.data(), internal.size());
  };
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line == "health") {
      assert(platform.trialActive());
      const Bytes before(flash.rawBuffer() + 0x192000, flash.rawBuffer() + 0x194000);
      assert(platform.health(0, false, true, true) == mesh::ota::OtaBoardTrialHealthOutcome::Pending);
      for (uint32_t now = 500; now < 10500; now += 50)
        assert(platform.health(now, true, true, true) == mesh::ota::OtaBoardTrialHealthOutcome::Pending);
      assert(NrfBootSafety::blank(confirm));
      assert(platform.health(10500, true, true, true) == mesh::ota::OtaBoardTrialHealthOutcome::Confirmed);
      assert(!std::memcmp(before.data(), flash.rawBuffer() + 0x192000, before.size()));
      RunningEvidence evidence;
      assert(platform.evidence(evidence) == Result::Ok && !(evidence.flags & RunningConfirmed));
    } else if (line != "flush") {
      const Bytes frame = unhex(line);
      const auto result = receiver.onFrame(frame.data(), frame.size());
      if (result != Result::Ok) std::cerr << "result=" << unsigned(result) << '\n';
    }
    for (unsigned i = 0; i < 2000; ++i) {
      const auto result = receiver.tick();
      if (result != Result::Ok) break;
    }
    size_t size;
    while (const uint8_t* frame = receiver.peek(size)) {
      static constexpr char hex[] = "0123456789abcdef";
      for (size_t i = 0; i < size; ++i) std::cout << hex[frame[i] >> 4] << hex[frame[i] & 15];
      std::cout << '\n'; receiver.release();
    }
    flush();
    std::cout << ".\n" << std::flush;
  }
  flush();
  assert(munmap(mapped, mappedSize) == 0);
}
