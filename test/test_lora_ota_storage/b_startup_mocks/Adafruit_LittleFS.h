#pragma once

#include <Stream.h>
#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

constexpr int LFS_ERR_NOENT = -2;
constexpr int LFS_ERR_IO = -5;
constexpr int LFS_ERR_CORRUPT = -84;
constexpr int FILE_O_WRITE = 1;

struct lfs_info {};
struct lfs_t {
  bool mounted = false;
  int mount_error = 0;
  int stat_error = 0;
  bool open_error = false;
  bool write_error = false;
  bool rename_error = false;
  size_t read_limit = SIZE_MAX;
  int mounts = 0, formats = 0, writes = 0, removes = 0, mkdirs = 0, stats = 0;
  std::map<std::string, std::shared_ptr<std::vector<uint8_t>>> files;
};

inline int lfs_stat(lfs_t* fs, const char* name, lfs_info*) {
  ++fs->stats;
  if (!fs->mounted) return LFS_ERR_IO;
  if (fs->stat_error) return fs->stat_error;
  return fs->files.count(name) ? 0 : LFS_ERR_NOENT;
}

namespace Adafruit_LittleFS_Namespace {

class File : public Stream {
  lfs_t* fs_ = nullptr;
  std::shared_ptr<std::vector<uint8_t>> data_;
  size_t pos_ = 0;
public:
  File() = default;
  File(lfs_t* fs, std::shared_ptr<std::vector<uint8_t>> data) : fs_(fs), data_(std::move(data)) {}
  explicit operator bool() const { return data_ != nullptr; }
  int available() override {
    return data_ ? static_cast<int>(std::min(fs_->read_limit, data_->size()) - pos_) : 0;
  }
  int read() override { return available() ? (*data_)[pos_++] : -1; }
  int read(uint8_t* dest, size_t count) {
    const size_t n = std::min(count, static_cast<size_t>(available()));
    if (n) memcpy(dest, data_->data() + pos_, n);
    pos_ += n;
    return static_cast<int>(n);
  }
  size_t write(const uint8_t* bytes, size_t count) override {
    if (!data_ || fs_->write_error) return 0;
    ++fs_->writes;
    data_->insert(data_->end(), bytes, bytes + count);
    return count;
  }
  void close() {}
};

}  // namespace Adafruit_LittleFS_Namespace

class Adafruit_LittleFS {
  lfs_t fs_;
public:
  lfs_t* _getFS() { return &fs_; }
  bool begin() {
    ++fs_.mounts;
    fs_.mounted = fs_.mount_error == 0;
    return fs_.mounted;
  }
  bool exists(const char* name) {
    lfs_info info;
    return lfs_stat(&fs_, name, &info) == 0;
  }
  bool mkdir(const char*) { ++fs_.mkdirs; return fs_.mounted; }
  bool remove(const char* name) {
    ++fs_.removes;
    fs_.files.erase(name);
    return true;
  }
  bool rename(const char* from, const char* to) {
    if (fs_.rename_error || !fs_.files.count(from)) return false;
    fs_.files[to] = fs_.files.at(from);
    fs_.files.erase(from);
    return true;
  }
  Adafruit_LittleFS_Namespace::File open(const char* name, int mode = 0) {
    if (!fs_.mounted || fs_.open_error) return {};
    if (mode == FILE_O_WRITE) {
      auto bytes = std::make_shared<std::vector<uint8_t>>();
      fs_.files[name] = bytes;
      return {&fs_, bytes};
    }
    auto it = fs_.files.find(name);
    return it == fs_.files.end() ? Adafruit_LittleFS_Namespace::File{}
                               : Adafruit_LittleFS_Namespace::File{&fs_, it->second};
  }
};

class InternalFileSystem : public Adafruit_LittleFS {
public:
  bool begin() {
    if (Adafruit_LittleFS::begin()) return true;
    lfs_t* fs = _getFS();
    ++fs->formats;
    fs->files.clear();
    fs->mount_error = 0;
    return Adafruit_LittleFS::begin();
  }
};
