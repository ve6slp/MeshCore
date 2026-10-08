#pragma once

#if !defined(FILESYSTEM)
#if defined(ESP32) || defined(RP2040_PLATFORM)
  #include <FS.h>
  #define FILESYSTEM  fs::FS
#elif defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  #include <Adafruit_LittleFS.h>
  #define FILESYSTEM  Adafruit_LittleFS

  using namespace Adafruit_LittleFS_Namespace;
#endif
#endif
#include <Identity.h>
#include "IdentityIntegrityCodec.h"

class IdentityStore {
  FILESYSTEM* _fs;
  const char* _dir;
  const char* _vfs_mount;
public:
  IdentityStore(FILESYSTEM& fs, const char* dir, const char* vfs_mount = nullptr)
      : _fs(&fs), _dir(dir), _vfs_mount(vfs_mount) { }

  void begin() {
     if (_dir && _dir[0] == '/') { _fs->mkdir(_dir); } }
  bool load(const char *name, mesh::LocalIdentity& id);
  bool load(const char *name, mesh::LocalIdentity& id, char display_name[], int max_name_sz);
  identity_io::LoadStatus loadWithStatus(const char* name, mesh::LocalIdentity& id, bool mounted);
  bool save(const char *name, const mesh::LocalIdentity& id);
  bool save(const char *name, const mesh::LocalIdentity& id, const char display_name[]);

  /**
   * \brief  bounded, side-effect-free MANDATORY-artifact integrity probe.
   *         Unlike load() (which goes through LocalIdentity::readFrom(Stream&),
   *         i.e. Stream::readBytes() -- which can internally loop/block up
   *         to its default ~1s timeout on a short/stalled file, and which
   *         only checks read-LENGTH, never the actual key CONTENT), this
   *         performs a single direct, bounded File::read() of the exact
   *         on-disk byte count and compares it against the identity
   *         ACTUALLY currently in RAM (`expected`) -- so a well-formed but
   *         WRONG/stale/foreign persisted identity is correctly reported
   *         as a fault, not silently accepted as healthy. Never logs key
   *         bytes. Never writes. Absence of the file IS a fault here (the
   *         caller is expected to only call this for an artifact that is
   *         known-mandatory, e.g. already unconditionally created/saved
   *         earlier in the current boot).
  */
  bool checkIntegrity(const char *name, mesh::LocalIdentity& expected) const;
};
