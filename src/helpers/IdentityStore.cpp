#include "IdentityStore.h"
#include "IdentityIntegrityCodec.h"
#if defined(ESP32)
#include <errno.h>
#include <sys/stat.h>
#endif

identity_io::LoadStatus IdentityStore::loadWithStatus(const char* name, mesh::LocalIdentity& id,
                                                     bool mounted) {
  if (!mounted) return identity_io::LoadStatus::Unavailable;
  char filename[40];
  const int filename_len = snprintf(filename, sizeof(filename), "%s/%s.id", _dir, name);
  if (filename_len < 0 || filename_len >= (int)sizeof(filename)) return identity_io::LoadStatus::Unreadable;
  identity_io::LoadStatus status;
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  struct lfs_info info;
  status = identity_io::classifyPathResult(true, lfs_stat(_fs->_getFS(), filename, &info),
                                          LFS_ERR_NOENT);
#elif defined(ESP32)
  if (_vfs_mount) {
    char vfs_filename[64];
    const int len = snprintf(vfs_filename, sizeof(vfs_filename), "%s%s", _vfs_mount, filename);
    if (len < 0 || len >= (int)sizeof(vfs_filename)) return identity_io::LoadStatus::Unreadable;
    struct stat info;
    const int result = stat(vfs_filename, &info);
    status = identity_io::classifyPathResult(true, result == 0 ? 0 : errno, ENOENT);
  } else {
    status = _fs->exists(filename) ? identity_io::LoadStatus::Unchecked
                                  : identity_io::LoadStatus::Unreadable;
  }
#else
  // This backend exposes no error-bearing stat: a failed exists() is unknown.
  status = _fs->exists(filename) ? identity_io::LoadStatus::Unchecked
                                : identity_io::LoadStatus::Unreadable;
#endif
  if (status != identity_io::LoadStatus::Unchecked) return status;
  mesh::LocalIdentity loaded;
  if (!load(name, loaded)) return identity_io::LoadStatus::Unreadable;
  id = loaded;
  return identity_io::LoadStatus::Loaded;
}

bool IdentityStore::load(const char *name, mesh::LocalIdentity& id) {
  bool loaded = false;
  char filename[40];
  sprintf(filename, "%s/%s.id", _dir, name);
  if (_fs->exists(filename)) {
#if defined(RP2040_PLATFORM)
    File file = _fs->open(filename, "r");
#else
    File file = _fs->open(filename);
#endif
    if (file) {
      loaded = id.readFrom(file);
      file.close();
    }
  }
  return loaded;
}

bool IdentityStore::load(const char *name, mesh::LocalIdentity& id, char display_name[], int max_name_sz) {
  bool loaded = false;
  char filename[40];
  sprintf(filename, "%s/%s.id", _dir, name);
  if (_fs->exists(filename)) {
#if defined(RP2040_PLATFORM)
    File file = _fs->open(filename, "r");
#else
    File file = _fs->open(filename);
#endif
    if (file) {
      loaded = id.readFrom(file);

      int n = max_name_sz;   // up to 32 bytes
      if (n > 32) n = 32;
      file.read((uint8_t *) display_name, n);
      display_name[n - 1] = 0;  // ensure null terminator

      file.close();
    }
  }
  return loaded;
}

bool IdentityStore::save(const char *name, const mesh::LocalIdentity& id) {
  char filename[40];
  sprintf(filename, "%s/%s.id", _dir, name);

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  _fs->remove(filename);
  File file = _fs->open(filename, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  File file = _fs->open(filename, "w");
#else
  File file = _fs->open(filename, "w", true);
#endif
  if (file) {
    // Real, already-performed write outcome -- a genuine short/failed
    // write here must not be reported as a successful save merely
    // because the file itself was opened.
    bool success = id.writeTo(file);
    file.close();
    MESH_DEBUG_PRINTLN("IdentityStore::save() write - %s", success ? "OK" : "Err");
    return success;
  }
  MESH_DEBUG_PRINTLN("IdentityStore::save() failed");
  return false;
}

bool IdentityStore::save(const char *name, const mesh::LocalIdentity& id, const char display_name[]) {
  char filename[40];
  sprintf(filename, "%s/%s.id", _dir, name);

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  _fs->remove(filename);
  File file = _fs->open(filename, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  File file = _fs->open(filename, "w");
#else
  File file = _fs->open(filename, "w", true);
#endif
  if (file) {
    // Real, already-performed write outcomes for BOTH the identity
    // bytes and the display-name blob -- a genuine short/failed write
    // on either must not be reported as a successful save.
    bool success = id.writeTo(file);

    uint8_t tmp[32];
    memset(tmp, 0, sizeof(tmp));
    int n = strlen(display_name);
    if (n > sizeof(tmp)-1) n = sizeof(tmp)-1;
    memcpy(tmp, display_name, n);
    success = success && (file.write(tmp, sizeof(tmp)) == sizeof(tmp));

    file.close();
    return success;
  }
  return false;
}

bool IdentityStore::checkIntegrity(const char *name, mesh::LocalIdentity& expected) const {
  char filename[40];
  sprintf(filename, "%s/%s.id", _dir, name);
  if (!_fs->exists(filename)) return false;  // mandatory artifact -- absence IS a fault here.

#if defined(RP2040_PLATFORM)
  File file = _fs->open(filename, "r");
#else
  File file = _fs->open(filename);
#endif
  if (!file) return false;  // exists() said yes but the open genuinely failed.

  // LocalIdentity::writeTo(uint8_t*, size_t) is the only PUBLIC accessor
  // to the private prv_key bytes; it serializes [prv_key][pub_key] (note:
  // reverse order from the on-disk Stream format below), so we ask it
  // for the expected bytes and compare field-by-field rather than
  // assuming a shared byte order. Performs no IO of its own.
  uint8_t expected_buf[PRV_KEY_SIZE + PUB_KEY_SIZE];
  size_t written = expected.writeTo(expected_buf, sizeof(expected_buf));
  if (written != sizeof(expected_buf)) { file.close(); return false; }

  // On-disk order is [pub_key(PUB_KEY_SIZE)][prv_key(PRV_KEY_SIZE)] (the
  // same order IdentityStore::save()/LocalIdentity::writeTo(Stream&)
  // already write) -- the shared identity_io::checkIdentityIntegrity()
  // performs the actual direct, bounded, single File::read() (never
  // Stream::readBytes()) and content comparison, never logging key
  // bytes.
  uint8_t disk_buf[PUB_KEY_SIZE + PRV_KEY_SIZE];
  const bool ok = identity_io::checkIdentityIntegrity(file, PUB_KEY_SIZE, PRV_KEY_SIZE,
                                                       expected_buf + PRV_KEY_SIZE,  // expected pub_key
                                                       expected_buf,                  // expected prv_key
                                                       disk_buf, sizeof(disk_buf));
  file.close();
  return ok;
}
