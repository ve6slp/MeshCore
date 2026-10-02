#pragma once

#include <Stream.h>
#include <algorithm>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <vector>

using lfs_block_t = uint32_t;
using lfs_size_t = uint32_t;
using lfs_ssize_t = int32_t;
struct lfs_config { uint32_t block_count = 128, block_size = 4096; };
struct lfs_t { const lfs_config* cfg; };
constexpr int LFS_ERR_CORRUPT = -84;
inline int lfs_traverse(lfs_t*, int (*)(void*, lfs_block_t), void*) { return 0; }

namespace Adafruit_LittleFS_Namespace {
constexpr int FILE_O_READ = 0, FILE_O_WRITE = 1;

class File : public Stream {
  std::shared_ptr<std::vector<uint8_t>> bytes_;
  size_t position_ = 0;
  uint32_t* writes_ = nullptr;
public:
  File() = default;
  File(std::shared_ptr<std::vector<uint8_t>> bytes, uint32_t* writes) : bytes_(bytes), writes_(writes) {}
  explicit operator bool() const { return bool(bytes_); }
  using Print::write;
  using Print::print;
  size_t print(unsigned char value, int base = DEC) override { return print(static_cast<unsigned long>(value), base); }
  size_t print(unsigned int value, int base = DEC) override { return print(static_cast<unsigned long>(value), base); }
  size_t print(int value, int base = DEC) override { return print(static_cast<long>(value), base); }
  size_t print(long value, int base = DEC) override {
    if (base != DEC) return print(static_cast<unsigned long>(value), base);
    char text[32]; std::snprintf(text, sizeof(text), "%ld", value); return write(text);
  }
  size_t print(unsigned long value, int base = DEC) override {
    char text[32]; std::snprintf(text, sizeof(text), base == HEX ? "%lx" : "%lu", value); return write(text);
  }
  size_t print(double value, int precision = 2) override {
    char text[64]; std::snprintf(text, sizeof(text), "%.*f", precision, value); return write(text);
  }
  size_t write(uint8_t byte) override { return write(&byte, 1); }
  size_t write(const uint8_t* bytes, size_t count) override {
    if (!bytes_) return 0;
    ++*writes_;
    if (position_ + count > bytes_->size()) bytes_->resize(position_ + count);
    std::copy(bytes, bytes + count, bytes_->begin() + position_);
    position_ += count;
    return count;
  }
  int available() override { return bytes_ ? int(bytes_->size() - position_) : 0; }
  int read() override {
    return available() ? (*bytes_)[position_++] : -1;
  }
  int peek() override { return available() ? (*bytes_)[position_] : -1; }
  int read(uint8_t* bytes, size_t count) {
    const size_t copied = std::min(count, size_t(available()));
    if (copied) std::copy_n(bytes_->data() + position_, copied, bytes);
    position_ += copied;
    return int(copied);
  }
  bool seek(size_t offset) { if (!bytes_ || offset > bytes_->size()) return false; position_ = offset; return true; }
  size_t position() const { return position_; }
  size_t size() const { return bytes_ ? bytes_->size() : 0; }
  void close() { bytes_.reset(); }
};
}

class Adafruit_LittleFS {
  lfs_config config_;
  lfs_t lfs_{&config_};
public:
  std::map<std::string, std::shared_ptr<std::vector<uint8_t>>> files;
  uint32_t writes = 0, removes = 0, formats = 0, mounts = 0;
  bool begin() { ++mounts; return true; }
  lfs_t* _getFS() { return &lfs_; }
  bool exists(const char* name) const { return files.count(name) != 0; }
  bool mkdir(const char*) { return true; }
  bool remove(const char* name) { ++removes; return files.erase(name) != 0; }
  bool format() { ++formats; files.clear(); return true; }
  Adafruit_LittleFS_Namespace::File open(const char* name, int mode = Adafruit_LittleFS_Namespace::FILE_O_READ) {
    if (!exists(name)) {
      if (mode != Adafruit_LittleFS_Namespace::FILE_O_WRITE) return {};
      files[name] = std::make_shared<std::vector<uint8_t>>();
    }
    return {files.at(name), &writes};
  }
};
