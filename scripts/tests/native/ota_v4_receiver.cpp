// Native process adapter around the same receiver used by RF and USB firmware.
// Keys supplied here are synthetic test keys, never read from device storage.
#include <helpers/ota/OtaV4Receiver.h>
#include <ota/trust/third_party/ed25519/Ed25519Impl.h>
#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace mesh::ota::v4;
namespace {
using Bytes = std::vector<uint8_t>;
bool unhex(const std::string& text, Bytes& out) {
  if (text.size() % 2) return false;
  out.clear();
  for (size_t i = 0; i < text.size(); i += 2) {
    auto digit = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    const int a = digit(text[i]), b = digit(text[i + 1]);
    if (a < 0 || b < 0) return false;
    out.push_back(static_cast<uint8_t>(a * 16 + b));
  }
  return true;
}
void putHash(Bytes& b) {
  uint8_t digest[32];
  ::ota::trust::Sha256::hash(b.data(), b.size(), digest);
  b.insert(b.end(), digest, digest + 32);
}
bool validHash(const Bytes& b) {
  if (b.size() < 32) return false;
  uint8_t digest[32];
  ::ota::trust::Sha256::hash(b.data(), b.size() - 32, digest);
  return !std::memcmp(digest, b.data() + b.size() - 32, 32);
}
Bytes transcript(const char* domain, size_t domainSize, const uint8_t* bytes, size_t size) {
  Bytes b;
  if (domainSize) b.insert(b.end(), domain, domain + domainSize);
  b.insert(b.end(), bytes, bytes + size);
  return b;
}

class FilePlatform final : public Platform {
public:
  FilePlatform(std::string directory, const Bytes& admin, const Bytes& seed) :
      directory_(std::move(directory)) {
    std::copy(admin.begin(), admin.end(), admin_);
    ::ota::trust::ed25519_impl::ed25519_create_keypair(identity_, private_, seed.data());
    floor_.flags = FloorKnown;
    Bytes bytes;
    Result r = readFile("evidence", bytes);
    if (r == Result::Ok) {
      if (bytes.size() != 69 || !validHash(bytes)) startup_ = Result::Integrity;
      else {
        floor_.floor = read32(bytes.data()); floor_.flags = bytes[4];
        std::memcpy(floor_.hash, bytes.data() + 5, 32);
      }
    } else if (r != Result::State) startup_ = r;
    bytes.clear();
    r = readFile("boot", bytes);
    if (r == Result::Ok) {
      if (bytes.size() != 97 || std::memcmp(bytes.data(), "V4B1", 4) || !validHash(bytes))
        startup_ = Result::Integrity;
      else boot_ = bytes;
    } else if (r != Result::State) startup_ = r;
  }

  Policy policy() const override {
    Policy p;
    p.boardFamily = 0x584e; p.boardVariant = 0x3430; p.role = 0;
    p.appAddress = 0x27000; p.maxImageBytes = kChunkBytes * kMaxChunks;
    p.bootloaderCapabilities = UINT32_MAX;
    return p;
  }
  Result identity(uint8_t out[32]) override {
    std::memcpy(out, identity_, 32); return Result::Ok;
  }
  Result evidence(RunningEvidence& out) override {
    if (startup_ != Result::Ok) return startup_;
    out = floor_; return Result::Ok;
  }
  Result random(uint8_t* out, size_t size) override {
    size_t offset = 0;
    while (offset < size) {
      const ssize_t got = getrandom(out + offset, size - offset, 0);
      if (got < 0 && errno == EINTR) continue;
      if (got <= 0) return Result::Io;
      offset += static_cast<size_t>(got);
    }
    return Result::Ok;
  }
  bool isCurrentAdmin(const uint8_t key[32]) override {
    return !revoked_ && !std::memcmp(key, admin_, 32);
  }
  bool verify(const uint8_t key[32], const char* domain, size_t domainSize,
              const uint8_t* bytes, size_t size, const uint8_t sig[64]) override {
    const Bytes b = transcript(domain, domainSize, bytes, size);
    return ::ota::trust::ed25519_impl::ed25519_verify(sig, b.data(), b.size(), key);
  }
  Result sign(const char* domain, size_t domainSize, const uint8_t* bytes,
              size_t size, uint8_t sig[64]) override {
    const Bytes b = transcript(domain, domainSize, bytes, size);
    ::ota::trust::ed25519_impl::ed25519_sign(sig, b.data(), b.size(), identity_, private_);
    return Result::Ok;
  }
  Result recover(Journal& out, uint8_t* manifest, size_t capacity, size_t& size) override {
    Bytes b;
    const Result r = readFile("journal", b);
    if (r != Result::Ok) return r;
    if (b.size() < 94 || std::memcmp(b.data(), "V4J1", 4) || !validHash(b))
      return Result::Integrity;
    size = read16(b.data() + 60);
    if (size > capacity || b.size() != 94 + size) return Result::Integrity;
    out.phase = static_cast<Phase>(b[4]); out.lastResult = static_cast<Result>(b[5]);
    out.nextChunk = read16(b.data() + 6); out.generation = read32(b.data() + 8);
    std::memcpy(out.packageHash, b.data() + 12, 32);
    std::memcpy(out.transaction, b.data() + 44, 16);
    std::memcpy(manifest, b.data() + 62, size);
    bound_ = out;
    return Result::Ok;
  }
  Result save(const Journal& j, const uint8_t* manifest, size_t size) override {
    if (failSave_) return Result::Io;
    if (size > kMaxManifestBytes) return Result::Invalid;
    Bytes b(62);
    std::memcpy(b.data(), "V4J1", 4); b[4] = static_cast<uint8_t>(j.phase);
    b[5] = static_cast<uint8_t>(j.lastResult); write16(b.data() + 6, j.nextChunk);
    write32(b.data() + 8, j.generation);
    std::memcpy(b.data() + 12, j.packageHash, 32);
    std::memcpy(b.data() + 44, j.transaction, 16);
    write16(b.data() + 60, size);
    if (size) b.insert(b.end(), manifest, manifest + size);
    putHash(b);
    const Result r = writeFile("journal", b);
    if (r == Result::Ok) bound_ = j;
    return r;
  }
  Result beginStaging(uint32_t size) override {
    const int fd = ::open(path("staging").c_str(), O_RDWR | O_CREAT, 0600);
    if (fd < 0) return Result::Io;
    const bool ok = !::ftruncate(fd, size) && !::fsync(fd);
    const bool closed = !::close(fd);
    return ok && closed ? Result::Ok : Result::Io;
  }
  Result writeStaging(uint32_t offset, const uint8_t* bytes, size_t size) override {
    if (failWrite_) return Result::Io;
    const int fd = ::open(path("staging").c_str(), O_RDWR);
    if (fd < 0) return Result::Io;
    const bool ok = ::pwrite(fd, bytes, size, offset) == static_cast<ssize_t>(size) && !::fsync(fd);
    const bool closed = !::close(fd);
    return ok && closed ? Result::Ok : Result::Io;
  }
  Result readStaging(uint32_t offset, uint8_t* bytes, size_t size) override {
    if (failRead_) return Result::Io;
    const int fd = ::open(path("staging").c_str(), O_RDONLY);
    if (fd < 0) return Result::Io;
    const bool ok = ::pread(fd, bytes, size, offset) == static_cast<ssize_t>(size);
    const bool closed = !::close(fd);
    return ok && closed ? Result::Ok : Result::Io;
  }
  Result clearStaging() override {
    return !::unlink(path("staging").c_str()) || errno == ENOENT ? Result::Ok : Result::Io;
  }
  Result repair(const Journal& idle) override {
    if (!boot_.empty() && (boot_[4] == static_cast<uint8_t>(Phase::ActivationPending) ||
                          boot_[4] == static_cast<uint8_t>(Phase::Trial))) return Result::State;
    Result r = save(idle, nullptr, 0);
    if (r != Result::Ok) return r;
    return clearStaging();
  }
  Result validateInstall(const uint8_t canonical[59], const uint8_t sig[64],
                         const uint8_t signer[32]) override {
    if (!isCurrentAdmin(signer) || !verify(signer, nullptr, 0, canonical, 59, sig))
      return Result::Denied;
    if (read32(canonical + 45) <= floor_.floor) return Result::Replay;
    uint8_t digest[32];
    Result r = stagingHash(read32(canonical + 9), digest);
    if (r != Result::Ok) return r;
    return std::memcmp(digest, canonical + 13, 32) ? Result::Integrity : Result::Ok;
  }
  Result activate(const uint8_t canonical[59], const uint8_t sig[64], const uint8_t signer[32],
                  const uint8_t transaction[16], uint32_t generation) override {
    const Result r = validateInstall(canonical, sig, signer);
    if (r != Result::Ok) return r;
    if (!boot_.empty() && boot_[4] != static_cast<uint8_t>(Phase::Confirmed)) {
      return !std::memcmp(boot_.data() + 45, transaction, 16) &&
          read32(boot_.data() + 61) == generation ? Result::Ok : Result::Busy;
    }
    Bytes b(65);
    std::memcpy(b.data(), "V4B1", 4); b[4] = static_cast<uint8_t>(Phase::ActivationPending);
    write32(b.data() + 5, read32(canonical + 9));
    write32(b.data() + 9, read32(canonical + 45));
    std::memcpy(b.data() + 13, canonical + 13, 32);
    std::memcpy(b.data() + 45, transaction, 16); write32(b.data() + 61, generation);
    putHash(b);
    const Result saved = writeFile("boot", b);
    if (saved == Result::Ok) boot_ = b;
    return saved;
  }
  Result lifecycle(Phase& phase) override {
    if (startup_ != Result::Ok) return startup_;
    if (boot_.empty() || boot_[4] == static_cast<uint8_t>(Phase::ActivationPending))
      return Result::State;
    if (std::memcmp(boot_.data() + 45, bound_.transaction, 16) ||
        read32(boot_.data() + 61) != bound_.generation) return Result::State;
    phase = static_cast<Phase>(boot_[4]); return Result::Ok;
  }
  Result lease(uint32_t, uint32_t, uint8_t, uint8_t, uint32_t) override {
    return Result::Ok; // Native has no radio; protocol authority is still checked.
  }
  Result confirm() {
    if (boot_.empty()) return Result::State;
    uint8_t digest[32];
    Result r = stagingHash(read32(boot_.data() + 5), digest);
    if (r != Result::Ok) return r;
    if (std::memcmp(digest, boot_.data() + 13, 32)) return Result::Integrity;
    floor_.floor = read32(boot_.data() + 9); floor_.flags = 7;
    std::memcpy(floor_.hash, digest, 32);
    Bytes e(37);
    write32(e.data(), floor_.floor); e[4] = floor_.flags;
    std::memcpy(e.data() + 5, floor_.hash, 32); putHash(e);
    r = writeFile("evidence", e);
    if (r != Result::Ok) return r;
    boot_.resize(65); boot_[4] = static_cast<uint8_t>(Phase::Confirmed); putHash(boot_);
    return writeFile("boot", boot_);
  }
  Result rollback() {
    if (boot_.empty() || boot_[4] != static_cast<uint8_t>(Phase::ActivationPending))
      return Result::State;
    boot_.resize(65); boot_[4] = static_cast<uint8_t>(Phase::Failed); putHash(boot_);
    return writeFile("boot", boot_);
  }
  void fault(const std::string& which) {
    failSave_ = which == "save"; failRead_ = which == "read"; failWrite_ = which == "write";
    revoked_ = which == "admin";
  }

private:
  std::string path(const char* name) const { return directory_ + "/" + name; }
  Result stagingHash(uint32_t expected, uint8_t digest[32]) {
    struct stat st{};
    if (::stat(path("staging").c_str(), &st) || st.st_size != expected) return Result::Io;
    ::ota::trust::Sha256 hash;
    uint8_t bytes[128];
    for (uint32_t offset = 0; offset < expected;) {
      const size_t size = std::min(size_t(128), size_t(expected - offset));
      const Result r = readStaging(offset, bytes, size);
      if (r != Result::Ok) return r;
      hash.update(bytes, size); offset += size;
    }
    hash.finish(digest); return Result::Ok;
  }
  Result readFile(const char* name, Bytes& out) {
    const int fd = ::open(path(name).c_str(), O_RDONLY);
    if (fd < 0) return errno == ENOENT ? Result::State : Result::Io;
    struct stat st{};
    if (::fstat(fd, &st) || st.st_size < 0 || st.st_size > 16384) {
      ::close(fd); return Result::Integrity;
    }
    out.resize(st.st_size);
    const bool ok = ::read(fd, out.data(), out.size()) == static_cast<ssize_t>(out.size());
    const bool closed = !::close(fd);
    return ok && closed ? Result::Ok : Result::Io;
  }
  Result writeFile(const char* name, const Bytes& bytes) {
    const std::string pending = path(name) + ".new";
    const int fd = ::open(pending.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return Result::Io;
    const bool ok = ::write(fd, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()) &&
        !::fsync(fd);
    const bool closed = !::close(fd);
    if (!ok || !closed || ::rename(pending.c_str(), path(name).c_str())) return Result::Io;
    const int dir = ::open(directory_.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir < 0) return Result::Io;
    const bool synced = !::fsync(dir);
    const bool dirClosed = !::close(dir);
    if (!synced || !dirClosed) return Result::Io;
    Bytes verify;
    const Result r = readFile(name, verify);
    return r == Result::Ok && verify == bytes ? Result::Ok : Result::Io;
  }
  std::string directory_;
  uint8_t admin_[32] = {}, identity_[32] = {}, private_[64] = {};
  RunningEvidence floor_;
  Journal bound_;
  Bytes boot_;
  Result startup_ = Result::Ok;
  bool failSave_ = false, failRead_ = false, failWrite_ = false, revoked_ = false;
};
}

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "usage: ota_v4_receiver <directory> <admin-pubkey-hex> <receiver-seed-hex>\n";
    return 2;
  }
  const std::string directory = argv[1];
  if (directory == "/tmp" || directory.compare(0, 5, "/tmp/") == 0 ||
      directory == "/var/tmp" || directory.compare(0, 9, "/var/tmp/") == 0) return 2;
  Bytes admin, seed;
  if (!unhex(argv[2], admin) || admin.size() != 32 ||
      !unhex(argv[3], seed) || seed.size() != 32) return 2;
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  if (error) return 2;
  FilePlatform platform(directory, admin, seed);
  std::unique_ptr<Receiver> receiver(new Receiver(platform));
  receiver->begin();
  std::string line;
  while (std::getline(std::cin, line)) {
    Result result = Result::Ok;
    if (line == "restart") {
      receiver.reset(new Receiver(platform)); result = receiver->begin();
    } else if (line == "confirm") {
      result = platform.confirm();
      if (result == Result::Ok) result = receiver->tick();
    } else if (line == "rollback") {
      result = platform.rollback();
      if (result == Result::Ok) result = receiver->tick();
    } else if (line == "tick") result = receiver->tick();
    else if (line.compare(0, 6, "fault ") == 0) platform.fault(line.substr(6));
    else {
      Bytes frame;
      if (line.size() > 2 * kMaxFrameBytes || !unhex(line, frame)) result = Result::Invalid;
      else {
        result = receiver->onFrame(frame.data(), frame.size());
      }
    }
    if (result != Result::Ok) std::cerr << "result=" << static_cast<unsigned>(result) << '\n';
    // Fast native time: ticks are independent of input acceptance, just as in
    // firmware. A rejected frame cannot stall recovery or an active decoder.
    if (line != "tick") {
      for (unsigned i = 0; i < 20000; ++i) {
        const Result step = receiver->tick();
        if (step != Result::Ok) {
          std::cerr << "tick-result=" << static_cast<unsigned>(step) << '\n';
          break;
        }
      }
    }
    size_t size;
    while (const uint8_t* frame = receiver->peek(size)) {
      static constexpr char hex[] = "0123456789abcdef";
      for (size_t i = 0; i < size; ++i) std::cout << hex[frame[i] >> 4] << hex[frame[i] & 15];
      std::cout << '\n'; receiver->release();
    }
    std::cout << ".\n" << std::flush;
  }
  return 0;
}
