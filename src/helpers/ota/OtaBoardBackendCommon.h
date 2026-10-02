#pragma once

// Shared logic for the two nRF52840+P25Q16H QSPI backend wiring files
// (variants/xiao_nrf52/OtaLabBackend.cpp and
// variants/sensecap_solar/OtaProductionBackend.cpp), extracted to avoid
// duplicating ~200 lines of near-identical MonotonicCounter/
// SignatureVerifier/InstallCommandProviderV2/boot-marker-qualification
// logic between the two boards. Board-specific target identities stay
// in each backend .cpp file. Unqualified boards expose only a signed
// uploader cache, without a fallback signer or installation authority.
//
// Header-only, dependency-free of Arduino/Ed25519 (the caller supplies its
// own ota::trust::SignatureVerifier implementation), so this can be
// exercised directly by PlatformIO's native unit tests.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <helpers/ota/OtaRfFrames.h>
#include <ota/runtime/OtaInstallAttemptIdentity.h>
#include <ota/storage/XiaoOtaActiveExtentBridge.h>
#include <ota/storage/XiaoOtaBootInfoReader.h>
#include <ota/storage/XiaoOtaCommandRecord.h>
#include <ota/storage/XiaoOtaTrialBootConfirmation.h>
#include <ota/storage/XiaoOtaTrialHealthMonitor.h>
#include <ota/trust/MonotonicCounter.h>
#include <ota/trust/ImageHasher.h>
#include <ota/trust/Sha256.h>
#include <ota/trust/SignatureVerifier.h>
#include <ota/trust/TrustTypes.h>
#include <helpers/ota/OtaFirmwareBackend.h>  // IOtaInstallCommandProviderV2
#include <helpers/ota/OtaFirmwareIntegration.h>

namespace mesh {
namespace ota {

class OtaNrf52FirmwareTrustProvider final : public OtaFirmwareTrustProvider {
public:
  using OtaFirmwareTrustProvider::OtaFirmwareTrustProvider;
  static constexpr uint32_t kMaximumImageBytes = 0xAD000u;

  bool verifyDescriptorPolicyOnly(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    return descriptor.exactSizeBytes <= kMaximumImageBytes &&
           OtaFirmwareTrustProvider::verifyDescriptorPolicyOnly(descriptor);
  }
};

// OTA profile changes must restart the wrapper's RX state as well as
// changing the chip. Otherwise STATE_RX can describe a chip left in
// standby by a RadioLib parameter setter, silently losing all blocks.
template<class PhysicalRadio, class Wrapper>
bool applyCheckedOtaRadioProfile(PhysicalRadio& radio, Wrapper& wrapper,
                                 float frequency, float bandwidth, uint8_t sf, uint8_t cr) {
  if (radio.standby() != 0 || radio.setFrequency(frequency) != 0 ||
      radio.setSpreadingFactor(sf) != 0 || radio.setBandwidth(bandwidth) != 0 ||
      radio.setCodingRate(cr) != 0) return false;
  wrapper.begin();
  const uint16_t preamble = Wrapper::preambleLengthForSF(sf);
  if (radio.setPreambleLength(preamble) != 0) return false;
  const auto timing = wrapper.calcMaxPacketMillis(sf, bandwidth, cr, preamble);
  radio.setPreambleMillis(timing.preambleMillis);
  radio.setMaxPayloadMillis(timing.payloadMillis);
  uint8_t unused = 0;
  wrapper.recvRaw(&unused, 0);
  return wrapper.isInRecvMode() && wrapper.probeDriverStatus();
}

// Durable-across-reset anti-rollback counter, shared by both backends.
// Fails closed (currentValue()/commitNewValue() both return false) unless
// the confirmed-counter floor is either (a) a valid record, or (b) both
// slots are genuinely blank/erased (legitimate first-ever-device
// baseline, counter=0) -- see
// XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed()'s doc
// comment for the corrupt-vs-blank distinction this depends on. A slot
// that is non-blank but fails validation (torn write, tampering) must
// NEVER be silently treated as "counter is 0"; that was the previous
// (fail-open) behavior this replaces.
class OtaBoardFailClosedMonotonicCounter : public ::ota::trust::MonotonicCounter {
public:
  explicit OtaBoardFailClosedMonotonicCounter(::ota::platform::FlashRegion& floor_region)
      : floor_region_(floor_region) {}

  // NOTE: this counter previously also supported an optional
  // `setRoleAuthority()` seam gating every read/commit behind a
  // publisher-signed `BootFloorActivationReceiptV1` lifetime-role record
  // (src/ota/authority/BootFloorActivationReceipt.h). That record format
  // belonged to the deleted parallel Authority/Store system and has been
  // removed as part of the lean identity-simplification migration -- see
  // docs/lora_ota_development.md. This class now always runs exactly the
  // "prior (numeric-floor-only)" behavior that was already its documented
  // fallback: fail closed unless the confirmed-counter floor is a valid
  // record or both slots are genuinely blank/erased. A durable minimal
  // signer-snapshot + manifest-hash install-command contract, if the Boot
  // owner's migration produces one, is a separate, future, explicitly
  // coordinated addition -- not a silent re-creation of this seam.
  bool currentValue(uint32_t& out) const override {
    ensureSeeded();
    if (!seed_ok_) return false;
    out = value_;
    return true;
  }

  bool commitNewValue(uint32_t value) override {
    ensureSeeded();
    if (!seed_ok_ || value <= value_) return false;
    value_ = value;
    return true;
  }

  bool initializedValue(uint32_t& out) const {
    return ::ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounter(floor_region_, out);
  }

private:
  void ensureSeeded() const {
    if (seeded_) return;
    seeded_ = true;
    uint32_t floor_value = 0;
    seed_ok_ = ::ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(floor_region_,
                                                                                         floor_value);
    if (seed_ok_) value_ = floor_value;
  }

  ::ota::platform::FlashRegion& floor_region_;
  mutable bool seeded_ = false;
  mutable bool seed_ok_ = false;
  mutable uint32_t value_ = 0;
};

// Reads a big-endian u32 out of the transport's own 59-byte canonical wire
// descriptor at the securityCounter field's fixed offset (boardFamily(2) +
// boardVariant(2) + role(1) + appAddress(4) + exactSizeBytes(4) +
// sha256(32) = 45), per encodeOtaDescriptorCanonical()'s field order --
// shared by both backends (was duplicated identically before).
inline uint32_t otaBoardWireDescriptorSecurityCounterBE(const uint8_t wire_descriptor[59]) {
  constexpr size_t kOffset = 2 + 2 + 1 + 4 + 4 + 32;  // = 45
  const uint8_t* p = wire_descriptor + kOffset;
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// First eight SHA256 bytes, interpreted BE64, over the no-NUL domain
// "MeshCore/OTA/install-attempt/v1", controller32, campaignBE32,
// sessionBE32, attemptBE16 and SHA256(canonical59).
// This pure derivation does not authenticate the supplied controller or
// authorize an attempt. The durable attempt owner must preserve the full
// binding and reject zero/colliding nonces before publishing a command.
inline uint64_t computeOtaTransactionNonce(const uint8_t controller[32],
                                           const meshcore::ota::runtime::OtaSessionId& session,
                                           const uint8_t wire_descriptor[59]) {
  return meshcore::ota::runtime::otaInstallAttemptNonce(controller, session, wire_descriptor);
}

// Supplies command v2's fields by copying the transport's own already-
// verified 59-byte wire descriptor + 64-byte Ed25519 signature verbatim
// (no re-signing), and resolving active_image_extent/hash via
// XiaoOtaActiveExtentBridge -- a fresh bank-0 read only, never a
// (possibly stale, wrong-sized after a USB reflash) floor record. Board-
// agnostic: both backends' prior copies were byte-for-byte identical.
class OtaBoardInstallCommandProviderV2 : public IOtaInstallCommandProviderV2 {
public:
  // Optional injected predicate: when set, buildInstallCommandV2() must
  // refuse (return false, write nothing) while a trial-boot health
  // window is genuinely active for this device -- a NEW install command
  // must never race a prior install whose trial-boot confirmation is
  // still pending (competing install during an active trial). Backends
  // wire their own OtaBoardTrialBootHealthConfirmer::isTrialActive() in
  // here via setTrialActivePredicate() once configured; left null (the
  // default) this predicate is simply not consulted.
  using TrialActivePredicate = bool (*)();
  void setTrialActivePredicate(TrialActivePredicate predicate) { trial_active_predicate_ = predicate; }

  bool buildInstallCommandV2(const uint8_t wire_descriptor[59], const uint8_t signature[64],
                             const meshcore::ota::runtime::OtaSessionId& session,
                             const uint8_t controller[32],
                             ::ota::storage::XiaoOtaCommandV2Fields& out) override {
    if (wire_descriptor == nullptr || signature == nullptr || controller == nullptr) return false;
    if (trial_active_predicate_ != nullptr && trial_active_predicate_()) {
      return false;  // refuse: a prior install's trial-boot confirmation is still pending.
    }
    const uint64_t nonce = computeOtaTransactionNonce(controller, session, wire_descriptor);
    if (nonce == 0) return false;
    const ::ota::storage::XiaoOtaActiveExtentInfo extent_info =
        ::ota::storage::XiaoOtaActiveExtentBridge::resolveCurrent();
    if (extent_info.active_image_extent == 0) {
      // resolveCurrent() returns 0 off-target OR whenever bank0 is not a
      // fresh, valid, CRC-verified record -- fail closed rather than
      // write a command with a bogus/guessed extent or hash.
      return false;
    }
    memcpy(out.wire_descriptor, wire_descriptor, sizeof(out.wire_descriptor));
    memcpy(out.signature_ed25519, signature, sizeof(out.signature_ed25519));
    out.active_image_extent = extent_info.active_image_extent;
    memcpy(out.active_image_hash_sha256, extent_info.active_image_hash_sha256,
           sizeof(out.active_image_hash_sha256));
    out.transaction_nonce = nonce;
    return true;
  }

private:
  TrialActivePredicate trial_active_predicate_ = nullptr;
};

// Command v3 binds a verified original snapshot and additionally carries the admitted signer into the
// new admitted_signer_public_key_ed25519 field: the Ed25519 public key
// of the already-verified manifest signer (see
// OtaFirmwareBackend.h's IOtaInstallCommandProviderV3 doc-comment -- this
// IS the sole sanctioned source for that field, never a wire-supplied or
// fabricated key). Board-agnostic: both backends' command-v3 wiring is
// byte-for-byte identical.
class IOtaNrf52OriginalSnapshotProvider {
public:
  virtual ~IOtaNrf52OriginalSnapshotProvider() = default;
  virtual bool readOriginalSnapshot(::ota::storage::XiaoOtaActiveExtentInfo& out) const = 0;
};

class OtaBoardInstallCommandProviderV3 : public IOtaInstallCommandProviderV3 {
public:
  OtaBoardInstallCommandProviderV3() = default;
  explicit OtaBoardInstallCommandProviderV3(const IOtaNrf52OriginalSnapshotProvider& original)
      : original_(&original) {}
  using TrialActivePredicate = bool (*)();
  void setTrialActivePredicate(TrialActivePredicate predicate) { trial_active_predicate_ = predicate; }

  bool buildInstallCommandV3(const uint8_t wire_descriptor[59], const uint8_t signature[64],
                             const uint8_t admitted_signer_public_key[32],
                             const meshcore::ota::runtime::OtaSessionId& session,
                             const uint8_t controller[32],
                             ::ota::storage::XiaoOtaCommandV3Fields& out) override {
    if (wire_descriptor == nullptr || signature == nullptr || controller == nullptr ||
        admitted_signer_public_key == nullptr) {
      return false;
    }
    if (trial_active_predicate_ != nullptr && trial_active_predicate_()) {
      return false;  // refuse: a prior install's trial-boot confirmation is still pending.
    }
    const uint64_t nonce = computeOtaTransactionNonce(controller, session, wire_descriptor);
    if (nonce == 0) return false;
    ::ota::storage::XiaoOtaActiveExtentInfo extent_info;
    if (original_) {
      if (!original_->readOriginalSnapshot(extent_info)) return false;
    } else {
      extent_info = ::ota::storage::XiaoOtaActiveExtentBridge::resolveCurrent();
    }
    if (extent_info.active_image_extent == 0) {
      // Same fail-closed rationale as V2: never write a command with a
      // bogus/guessed extent or hash.
      return false;
    }
    memcpy(out.wire_descriptor, wire_descriptor, sizeof(out.wire_descriptor));
    memcpy(out.admitted_signer_public_key_ed25519, admitted_signer_public_key,
           sizeof(out.admitted_signer_public_key_ed25519));
    memcpy(out.signature_ed25519, signature, sizeof(out.signature_ed25519));
    out.active_image_extent = extent_info.active_image_extent;
    memcpy(out.active_image_hash_sha256, extent_info.active_image_hash_sha256,
           sizeof(out.active_image_hash_sha256));
    out.transaction_nonce = nonce;
    return true;
  }

private:
  TrialActivePredicate trial_active_predicate_ = nullptr;
  const IOtaNrf52OriginalSnapshotProvider* original_ = nullptr;
};

struct OtaNrf52RunningContext {
  uint8_t settings[::ota::storage::XiaoOtaActiveExtentBridge::kBootloaderSettingsRawBytes] = {};
  const uint8_t* image = nullptr;
  uint32_t capacity = 0;
  bool settingsTailErased = false;
};

class IOtaNrf52RunningContext {
public:
  virtual ~IOtaNrf52RunningContext() = default;
  virtual bool read(OtaNrf52RunningContext& out) const = 0;
};

class OtaBoardNrf52RunningContext final : public IOtaNrf52RunningContext {
public:
  bool read(OtaNrf52RunningContext& out) const override {
    out = OtaNrf52RunningContext();
#if defined(NRF52840_XXAA)
    const auto* settings = reinterpret_cast<const uint8_t*>(0x000FF000u);
    memcpy(out.settings, settings, sizeof(out.settings));
    out.image = reinterpret_cast<const uint8_t*>(::ota::storage::kXiaoOtaAppStart);
    out.capacity = ::ota::storage::kXiaoOtaAppInstallMaxSize;
    out.settingsTailErased = true;
    for (uint32_t i = sizeof(out.settings); i < 4096; ++i) {
      if (settings[i] != 0xff) { out.settingsTailErased = false; break; }
    }
    return true;
#else
    return false;
#endif
  }
};

// Original backups bind the same four-byte-rounded extent as xiao_ota_safe_backup_extent().
// This snapshot is not trial/candidate verification or installation authority.
struct OtaBoardOriginalImageSnapshot {
  OtaNrf52RunningContext running;
  ::ota::storage::XiaoOtaActiveExtentInfo image;
  uint16_t computedCrc = 0;
  uint8_t stateWindowHash[32] = {};
  uint8_t floorWindowHash[32] = {};
  uint32_t protectedFloor = 0;
  static bool resolve(const OtaNrf52RunningContext& source, OtaBoardOriginalImageSnapshot& out) {
    using Bridge = ::ota::storage::XiaoOtaActiveExtentBridge;
    out = OtaBoardOriginalImageSnapshot();
    const auto bank = Bridge::decodeBank0FromRaw28Bytes(source.settings);
    const uint16_t bank1 = source.settings[4] | (uint16_t(source.settings[5]) << 8);
    if (!source.settingsTailErased || (bank1 != 0xfe && bank1 != 0xff) ||
        bank.bank_0 != ::ota::storage::kBankValidApp || !source.image || bank.bank_0_size < 8 ||
        bank.bank_0_size > ::ota::storage::kXiaoOtaAppInstallMaxSize ||
        bank.bank_0_size > meshcore::ota::runtime::kOtaMaxImageBytes) return false;
    const uint32_t extent = (bank.bank_0_size + 3u) & ~uint32_t(3);
    if (extent > source.capacity || extent > ::ota::storage::kXiaoOtaAppInstallMaxSize) return false;
    bool empty_vectors = true;
    for (uint32_t i = 0; i < 8; ++i) if (source.image[i] != 0xff) empty_vectors = false;
    if (empty_vectors) return false;
    const auto crc = Bridge::crc16Compute(source.image, bank.bank_0_size);
    if (bank.bank_0_crc && bank.bank_0_crc != crc) return false;
    out.running = source;
    out.computedCrc = crc;
    out.image.active_image_extent = extent;
    Bridge::computeFreshHash(source.image, extent, out.image.active_image_hash_sha256);
    return true;
  }
};

inline usb::UsbOtaResult inspectOtaBoardStateWindows(const ::ota::platform::FlashRegion& region,
    const uint8_t* newest, ::ota::storage::XiaoOtaStateReader::ReadStatus status,
    uint64_t excluded_nonce, uint8_t digest[32]) {
  using State = ::ota::storage::XiaoOtaStateReader;
  using Result = usb::UsbOtaResult;
  const auto le32 = [](const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
  };
  constexpr uint32_t sidecar_offset = 0x100, sidecar_bytes = 88;
  if (region.eraseUnitBytes() < sidecar_offset + sidecar_bytes) return Result::TooLate;
  ::ota::trust::Sha256 hash;
  for (uint32_t slot = 0; slot < 2; ++slot) {
    const uint32_t offset = slot * region.eraseUnitBytes();
    uint8_t prefix[sidecar_offset], sidecar[sidecar_bytes];
    if (!::ota::platform::isOk(region.read(offset, prefix, sizeof(prefix))) ||
        !::ota::platform::isOk(region.read(offset + sidecar_offset, sidecar, sizeof(sidecar))))
      return Result::IoError;
    hash.update(prefix, sizeof(prefix)); hash.update(sidecar, sizeof(sidecar));
    const bool valid = State::isValidRecord(prefix, State::kRecordBytes);
    if (valid) {
      const uint32_t sequence = le32(prefix + 8), latest_sequence = le32(newest + 8);
      const auto phase = State::phase(prefix);
      const bool terminal = phase == 0 || phase == State::kPhaseConfirmed || phase == State::kPhaseFailedMax;
      if (status != State::ReadStatus::Found ||
          (excluded_nonce && State::transactionNonce(prefix) == excluded_nonce) || sequence > latest_sequence ||
          (!terminal && (sequence >= latest_sequence ||
                         State::transactionNonce(prefix) != State::transactionNonce(newest))))
        return Result::TooLate;
    } else {
      for (uint32_t i = 0; i < State::kRecordBytes; ++i) if (prefix[i] != 0xff) return Result::TooLate;
    }
    for (uint32_t i = State::kRecordBytes; i < sizeof(prefix); ++i) if (prefix[i] != 0xff) return Result::TooLate;
    bool sidecar_blank = true;
    for (const auto byte : sidecar) if (byte != 0xff) sidecar_blank = false;
    if (!sidecar_blank &&
        (!valid || le32(sidecar) != 0x58534944 || sidecar[4] != 1 || sidecar[5] ||
         sidecar[6] != sidecar_bytes || sidecar[7] ||
         le32(sidecar + 80) != ::ota::storage::Crc32::computeFinalized(sidecar, 80) ||
         le32(sidecar + 84) != State::kCommitMarker || memcmp(sidecar + 8, prefix + 8, 12) ||
         memcmp(sidecar + 52, prefix + 36, 4) || memcmp(sidecar + 60, prefix + 40, 4)))
      return Result::TooLate;
    uint8_t bytes[256];
    for (uint32_t done = sidecar_offset + sidecar_bytes; done < region.eraseUnitBytes();) {
      const uint32_t n = region.eraseUnitBytes() - done < sizeof(bytes) ?
          region.eraseUnitBytes() - done : sizeof(bytes);
      if (!::ota::platform::isOk(region.read(offset + done, bytes, n))) return Result::IoError;
      hash.update(bytes, n);
      for (uint32_t i = 0; i < n; ++i) if (bytes[i] != 0xff) return Result::TooLate;
      done += n;
    }
  }
  hash.finish(digest);
  return Result::Ok;
}

inline bool verifyOtaBoardNrfManifest(const uint8_t canonical[59], const uint8_t signature[64],
    const uint8_t owner[32], const ::ota::trust::SignatureVerifier& signatures,
    uint32_t target, uint32_t role, uint32_t capacity, meshcore::ota::protocol::OtaDescriptor& descriptor) {
  using namespace meshcore::ota::protocol;
  return decodeOtaDescriptorCanonical(canonical, 59, descriptor) == OtaDescriptorCodecResult::Ok &&
      descriptor.boardFamily == (target >> 16) && descriptor.boardVariant == (target & 0xffff) &&
      descriptor.role == role && descriptor.formatId == 1 && descriptor.algorithmId == 1 && descriptor.keyId &&
      !(descriptor.minBootloaderCapabilities & ~1u) && descriptor.appAddress == ::ota::storage::kXiaoOtaAppStart &&
      descriptor.exactSizeBytes && descriptor.exactSizeBytes <= OtaNrf52FirmwareTrustProvider::kMaximumImageBytes &&
      descriptor.exactSizeBytes <= capacity && signatures.verify(signature, 64, canonical, 59, owner, 32);
}

class OtaBoardOriginalSnapshotProvider final : public IOtaNrf52OriginalSnapshotProvider {
public:
  using State = ::ota::storage::XiaoOtaStateReader;
  enum class Context { None, FactoryFloor, Confirmed, RestoredOriginal };
  enum class FloorInitialization { Blank, Initialized, Unproven };
  OtaBoardOriginalSnapshotProvider(::ota::platform::FlashRegion& state, ::ota::platform::FlashRegion& floor,
      const IOtaNrf52RunningContext& running, const bool& qualified)
      : state_(state), floor_(floor), running_(running), qualified_(qualified) {}
  FloorInitialization floorInitialization() const {
    using Floor = ::ota::storage::XiaoOtaFloorReader;
    if (!floor_.isValid() || floor_.sizeBytes() != 2u * floor_.eraseUnitBytes() ||
        floor_.eraseUnitBytes() < Floor::kRecordBytes) return FloorInitialization::Unproven;
    bool all_blank = true, initialized = false;
    uint8_t bytes[256];
    for (uint32_t slot = 0; slot < 2; ++slot) {
      for (uint32_t offset = 0; offset < floor_.eraseUnitBytes();) {
        const uint32_t n = floor_.eraseUnitBytes() - offset < sizeof(bytes) ?
            floor_.eraseUnitBytes() - offset : sizeof(bytes);
        if (!::ota::platform::isOk(floor_.read(slot * floor_.eraseUnitBytes() + offset, bytes, n)))
          return FloorInitialization::Unproven;
        if (!offset && Floor::isValidRecord(bytes, Floor::kRecordBytes)) initialized = true;
        for (uint32_t i = 0; i < n; ++i) if (bytes[i] != 0xff) all_blank = false;
        offset += n;
      }
    }
    return initialized ? FloorInitialization::Initialized :
        all_blank ? FloorInitialization::Blank : FloorInitialization::Unproven;
  }
  bool readOriginalSnapshot(::ota::storage::XiaoOtaActiveExtentInfo& out) const override {
    OtaBoardOriginalImageSnapshot snapshot;
    Context context;
    if (!read(snapshot, context)) { out = ::ota::storage::XiaoOtaActiveExtentInfo(); return false; }
    out = snapshot.image;
    return true;
  }
  bool read(OtaBoardOriginalImageSnapshot& out, Context& context) const {
    out = OtaBoardOriginalImageSnapshot(); context = Context::None;
    if (!qualified_) return false;
    uint8_t state[State::kRecordBytes] = {}, latest[State::kRecordBytes] = {};
    const auto status = State::readNewestWithStatus(state_, state);
    if (status != State::ReadStatus::Blank && status != State::ReadStatus::Found) return false;
    if (status == State::ReadStatus::Found && State::phase(state) != State::kPhaseConfirmed &&
        State::phase(state) != State::kPhaseFailedMax) return false;
    uint8_t state_digest[32], latest_digest[32];
    if (inspectOtaBoardStateWindows(state_, state, status, 0, state_digest) != usb::UsbOtaResult::Ok) return false;
    uint32_t floor = 0, floor_extent = 0, latest_floor = 0, latest_extent = 0;
    uint8_t floor_hash[32], latest_hash[32], floor_digest[32], latest_floor_digest[32];
    bool genesis = false, latest_genesis = false;
    if (!readFloorEvidence(floor, floor_extent, floor_hash, floor_digest, genesis)) return false;
    OtaNrf52RunningContext before, after;
    OtaBoardOriginalImageSnapshot first, second;
    if (!running_.read(before) || !OtaBoardOriginalImageSnapshot::resolve(before, first)) return false;
    using Bridge = ::ota::storage::XiaoOtaActiveExtentBridge;
    const auto bank = Bridge::decodeBank0FromRaw28Bytes(before.settings);
    uint8_t actual_floor_hash[32] = {};
    if (!genesis) {
      if (floor_extent != bank.bank_0_size && floor_extent != first.image.active_image_extent) return false;
      Bridge::computeFreshHash(before.image, floor_extent, actual_floor_hash);
      if (memcmp(actual_floor_hash, floor_hash, 32)) return false;
    }
    uint8_t saved_sdk[28] = {}, rechecked_sdk[28] = {};
    if (status == State::ReadStatus::Blank) {
      // A real boot-owned floor0 record is required; a blank floor is never genesis.
      if (floor) return false;
      context = Context::FactoryFloor;
    } else if (State::phase(state) == State::kPhaseConfirmed) {
      if (!floor || !State::transactionNonce(state) || floor != State::candidateCounter(state) ||
          floor_extent != bank.bank_0_size || bank.bank_0_crc != first.computedCrc ||
          memcmp(State::candidateHashSha256(state), actual_floor_hash, 32) ||
          memcmp(State::installedHashSha256(state), actual_floor_hash, 32)) return false;
      context = Context::Confirmed;
    } else {
      if (!State::transactionNonce(state) || State::candidateCounter(state) <= floor ||
          State::activeImageExtent(state) != first.image.active_image_extent ||
          memcmp(state + 76, first.image.active_image_hash_sha256, 32) ||
          !readSavedOriginalSettings(state, saved_sdk) ||
          memcmp(saved_sdk, before.settings, sizeof(saved_sdk))) return false;
      context = Context::RestoredOriginal;
    }
    if (State::readNewestWithStatus(state_, latest) != status || memcmp(state, latest, sizeof(state)) ||
        !running_.read(after) || !OtaBoardOriginalImageSnapshot::resolve(after, second) ||
        memcmp(before.settings, after.settings, sizeof(before.settings)) ||
        before.image != after.image || before.capacity != after.capacity ||
        before.settingsTailErased != after.settingsTailErased ||
        first.computedCrc != second.computedCrc ||
        first.image.active_image_extent != second.image.active_image_extent ||
        memcmp(first.image.active_image_hash_sha256, second.image.active_image_hash_sha256, 32) ||
        inspectOtaBoardStateWindows(state_, latest, status, 0, latest_digest) != usb::UsbOtaResult::Ok ||
        memcmp(state_digest, latest_digest, 32) ||
        !readFloorEvidence(latest_floor, latest_extent, latest_hash, latest_floor_digest, latest_genesis) ||
        floor != latest_floor || floor_extent != latest_extent || memcmp(floor_hash, latest_hash, 32) ||
        genesis != latest_genesis || memcmp(floor_digest, latest_floor_digest, 32) ||
        (context == Context::RestoredOriginal &&
         (!readSavedOriginalSettings(latest, rechecked_sdk) || memcmp(saved_sdk, rechecked_sdk, 28)))) {
      context = Context::None;
      return false;
    }
    out = second;
    memcpy(out.stateWindowHash, state_digest, 32);
    memcpy(out.floorWindowHash, floor_digest, 32);
    out.protectedFloor = floor;
    return true;
  }
  bool ordinaryWritesAllowed(const ::ota::platform::FlashRegion& command,
      const ::ota::platform::FlashRegion& confirm, const ::ota::trust::SignatureVerifier& signatures,
      uint32_t target, uint32_t role) const {
    using Command = ::ota::storage::XiaoOtaCommandRecordV3;
    OtaBoardOriginalImageSnapshot snapshot;
    Context context;
    if (!read(snapshot, context) || !Command::regionIsValid(command)) return false;
    uint8_t state[State::kRecordBytes] = {}, records[2][Command::kRecordBytes];
    if (State::readNewestWithStatus(state_, state) !=
        (context == Context::FactoryFloor ? State::ReadStatus::Blank : State::ReadStatus::Found)) return false;
    uint32_t floor = 0;
    if (!::ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(floor_, floor)) return false;
    bool valid[2] = {};
    meshcore::ota::protocol::OtaDescriptor descriptors[2];
    int newest = -1;
    uint8_t digest[32], latest_digest[32];
    if (!hashCommandWindows(command, records, digest)) return false;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      valid[slot] = Command::isValidRecord(records[slot], sizeof(records[slot]));
      if (!valid[slot]) continue;
      if (context == Context::FactoryFloor) return false;
      auto& d = descriptors[slot];
      if (!verifyOtaBoardNrfManifest(Command::wireDescriptorOf(records[slot]), Command::signatureOf(records[slot]),
          Command::admittedSignerKeyOf(records[slot]), signatures, target, role,
          OtaNrf52FirmwareTrustProvider::kMaximumImageBytes, d)) return false;
      if (newest < 0 || sequenceNewer(Command::sequenceOf(records[slot]), Command::sequenceOf(records[newest])))
        newest = slot;
    }
    for (uint32_t slot = 0; slot < 2; ++slot) {
      if (!valid[slot] || descriptors[slot].securityCounter <= floor) continue;
      if (context != Context::RestoredOriginal || newest < 0 ||
          State::transactionNonce(state) != Command::transactionNonceOf(records[newest]) ||
          State::candidateCounter(state) != descriptors[newest].securityCounter ||
          memcmp(State::candidateHashSha256(state), descriptors[newest].sha256, 32) ||
          (slot != uint32_t(newest) &&
           !sequenceNewer(Command::sequenceOf(records[newest]), Command::sequenceOf(records[slot])))) return false;
    }
    if (context == Context::FactoryFloor && !blankRegion(confirm)) return false;
    uint8_t latest_records[2][Command::kRecordBytes];
    OtaBoardOriginalImageSnapshot latest;
    Context latest_context;
    return hashCommandWindows(command, latest_records, latest_digest) &&
        !memcmp(digest, latest_digest, 32) && read(latest, latest_context) && latest_context == context &&
        !memcmp(snapshot.running.settings, latest.running.settings, sizeof(snapshot.running.settings)) &&
        snapshot.protectedFloor == latest.protectedFloor &&
        !memcmp(snapshot.stateWindowHash, latest.stateWindowHash, 32) &&
        !memcmp(snapshot.floorWindowHash, latest.floorWindowHash, 32) &&
        snapshot.image.active_image_extent == latest.image.active_image_extent &&
        !memcmp(snapshot.image.active_image_hash_sha256, latest.image.active_image_hash_sha256, 32) &&
        (context != Context::FactoryFloor || blankRegion(confirm));
  }
  bool readSavedOriginalSettings(const uint8_t state[State::kRecordBytes], uint8_t out[28]) const {
    const auto& region = state_;
    if (!State::regionIsValid(region) || region.eraseUnitBytes() < 344) return false;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      uint8_t record[State::kRecordBytes], sidecar[88];
      const uint32_t offset = slot * region.eraseUnitBytes();
      if (!::ota::platform::isOk(region.read(offset, record, sizeof(record)))) return false;
      if (memcmp(record, state, sizeof(record))) continue;
      if (!::ota::platform::isOk(region.read(offset + 0x100, sidecar, sizeof(sidecar)))) return false;
      if (le32(sidecar) != 0x58534944 || sidecar[4] != 1 || sidecar[5] ||
          sidecar[6] != sizeof(sidecar) || sidecar[7] ||
          le32(sidecar + 80) != ::ota::storage::Crc32::computeFinalized(sidecar, 80) ||
          le32(sidecar + 84) != State::kCommitMarker ||
          memcmp(sidecar + 8, state + 8, 12) ||
          memcmp(sidecar + 52, state + 36, 4) || memcmp(sidecar + 60, state + 40, 4)) return false;
      // XSID20 is the historical command digest, not SDK28 or the replaceable current command.
      memcpy(out, sidecar + 52, 28);
      return true;
    }
    return false;
  }
private:
  bool readFloorEvidence(uint32_t& counter, uint32_t& extent, uint8_t image_hash[32],
      uint8_t digest[32], bool& genesis) const {
    using Floor = ::ota::storage::XiaoOtaFloorReader;
    if (!floor_.isValid() || floor_.sizeBytes() != 2u * floor_.eraseUnitBytes() ||
        floor_.eraseUnitBytes() < Floor::kRecordBytes) return false;
    uint32_t sequence = 0, valid_count = 0;
    bool invalid = false, tails_blank = true;
    ::ota::trust::Sha256 hash;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      const uint32_t base = slot * floor_.eraseUnitBytes();
      uint8_t record[Floor::kRecordBytes], bytes[256];
      if (!::ota::platform::isOk(floor_.read(base, record, sizeof(record)))) return false;
      hash.update(record, sizeof(record));
      if (Floor::isValidRecord(record, sizeof(record))) {
        const uint32_t next = le32(record + 8);
        if (!valid_count || next >= sequence) {
          sequence = next; counter = le32(record + 12); extent = le32(record + 16);
          memcpy(image_hash, record + 20, 32);
        }
        ++valid_count;
      } else {
        for (const auto byte : record) if (byte != 0xff) invalid = true;
      }
      for (uint32_t done = sizeof(record); done < floor_.eraseUnitBytes();) {
        const uint32_t n = floor_.eraseUnitBytes() - done < sizeof(bytes) ?
            floor_.eraseUnitBytes() - done : sizeof(bytes);
        if (!::ota::platform::isOk(floor_.read(base + done, bytes, n))) return false;
        hash.update(bytes, n);
        for (uint32_t i = 0; i < n; ++i) if (bytes[i] != 0xff) tails_blank = false;
        done += n;
      }
    }
    if (!valid_count) return false;
    genesis = !counter && !extent;
    if (genesis) {
      // Only the boot's single sequence1, counter0/extent0/hash0 record is genesis.
      if (sequence != 1 || valid_count != 1 || invalid || !tails_blank) return false;
      for (uint32_t i = 0; i < 32; ++i) if (image_hash[i]) return false;
    } else if (!extent) {
      return false;
    }
    hash.finish(digest);
    return true;
  }
  static bool blankRegion(const ::ota::platform::FlashRegion& region) {
    if (!region.isValid()) return false;
    uint8_t bytes[256];
    for (uint32_t offset = 0; offset < region.sizeBytes();) {
      const uint32_t size = region.sizeBytes() - offset < sizeof(bytes) ? region.sizeBytes() - offset : sizeof(bytes);
      if (!::ota::platform::isOk(region.read(offset, bytes, size))) return false;
      for (uint32_t i = 0; i < size; ++i) if (bytes[i] != 0xff) return false;
      offset += size;
    }
    return true;
  }
  static bool sequenceNewer(uint32_t next, uint32_t previous) {
    const uint32_t difference = next - previous;
    return difference && difference < 0x80000000u;
  }
  static bool hashCommandWindows(const ::ota::platform::FlashRegion& region,
      uint8_t records[2][::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes], uint8_t digest[32]) {
    using Command = ::ota::storage::XiaoOtaCommandRecordV3;
    ::ota::trust::Sha256 hash;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      const uint32_t base = slot * region.eraseUnitBytes();
      if (!::ota::platform::isOk(region.read(base, records[slot], Command::kRecordBytes))) return false;
      hash.update(records[slot], Command::kRecordBytes);
      if (!Command::isValidRecord(records[slot], Command::kRecordBytes))
        for (uint32_t i = 0; i < Command::kRecordBytes; ++i) if (records[slot][i] != 0xff) return false;
      uint8_t bytes[256];
      for (uint32_t offset = Command::kRecordBytes; offset < region.eraseUnitBytes();) {
        const uint32_t size = region.eraseUnitBytes() - offset < sizeof(bytes) ?
            region.eraseUnitBytes() - offset : sizeof(bytes);
        if (!::ota::platform::isOk(region.read(base + offset, bytes, size))) return false;
        hash.update(bytes, size);
        for (uint32_t i = 0; i < size; ++i) if (bytes[i] != 0xff) return false;
        offset += size;
      }
    }
    hash.finish(digest);
    return true;
  }
  static uint32_t le32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
  }
  ::ota::platform::FlashRegion& state_;
  ::ota::platform::FlashRegion& floor_;
  const IOtaNrf52RunningContext& running_;
  const bool& qualified_;
};

// Explicit signed ABORT is the only cancellation authority. BootUnknown alone is never evidence.
class OtaBoardUnadmittedCommandRecovery {
public:
  using Result = usb::UsbOtaResult;
  using Store = ::ota::storage::OtaCandidateStore;
  using Command = ::ota::storage::XiaoOtaCommandRecordV3;
  using State = ::ota::storage::XiaoOtaStateReader;
  OtaBoardUnadmittedCommandRecovery(::ota::platform::FlashRegion& command, ::ota::platform::FlashRegion& state,
      ::ota::platform::FlashRegion& floor, ::ota::platform::FlashRegion& image,
      const ::ota::trust::SignatureVerifier& signatures, const IOtaNrf52RunningContext& running,
      const bool& qualified, uint32_t target, uint32_t role)
      : command_(command), state_(state), floor_(floor), image_(image), signatures_(signatures),
        running_(running), qualified_(qualified), target_(target), role_(role) {}
  static Result invoke(void* ctx, const Store::Snapshot& candidate, bool cancel) {
    return static_cast<OtaBoardUnadmittedCommandRecovery*>(ctx)->recover(candidate, cancel);
  }

  Result recover(const Store::Snapshot& candidate, bool cancel) {
    if (!qualified_ || !candidate.valid || candidate.localCache || !Command::regionIsValid(command_))
      return Result::TooLate;
    meshcore::ota::protocol::OtaDescriptor descriptor;
    if (!authentic(candidate.canonical, candidate.signature, candidate.ownerPublicKey, descriptor) ||
        candidate.exactSizeBytes != descriptor.exactSizeBytes ||
        candidate.totalBlocks != (descriptor.exactSizeBytes + kOtaBlockMaxDataBytes - 1) / kOtaBlockMaxDataBytes)
      return Result::TooLate;
    auto bound = candidate;
    if (candidate.phase == Store::Phase::Aborted) {
      if (!bound.sessionId) return Result::TooLate;
      --bound.sessionId;
    }
    const auto expected = OtaLeanReceiver::snapshotStatus(bound);
    if (!expected.transactionNonce || !expected.counter) return Result::TooLate;
    uint8_t state[State::kRecordBytes] = {};
    const auto state_status = State::readNewestWithStatus(state_, state);
    if (state_status == State::ReadStatus::Unknown) return Result::IoError;
    if (state_status != State::ReadStatus::Blank && state_status != State::ReadStatus::Found)
      return Result::TooLate;
    if (state_status == State::ReadStatus::Found &&
        ((State::phase(state) != 0 && State::phase(state) != State::kPhaseConfirmed &&
          State::phase(state) != State::kPhaseFailedMax) ||
         State::transactionNonce(state) == expected.transactionNonce)) return Result::TooLate;
    uint8_t state_digest[32];
    const auto checked_state = inspectStateWindows(state, state_status, expected.transactionNonce, state_digest);
    if (checked_state != Result::Ok) return checked_state;
    bool ignored = false;
    uint32_t floor = 0;
    if (!::ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(floor_, floor))
      return Result::IoError;
    if (state_status == State::ReadStatus::Found && State::phase(state) == State::kPhaseConfirmed &&
        State::candidateCounter(state) > floor) return Result::TooLate;
    OtaNrf52RunningContext before, after;
    if (!running_.read(before)) return Result::IoError;
    // Pinned SDK11 BANK_ERASED/BANK_INVALID_APP; every copy/pending/unknown bank-1 code is refused.
    const uint16_t bank1 = before.settings[4] | (uint16_t(before.settings[5]) << 8);
    if (bank1 != 0xfe && bank1 != 0xff) return Result::TooLate;
    const auto bank0 = ::ota::storage::XiaoOtaActiveExtentBridge::decodeBank0FromRaw28Bytes(before.settings);
    using Bridge = ::ota::storage::XiaoOtaActiveExtentBridge;
    auto current = Bridge::resolve(bank0, before.image, before.capacity);
    const bool original_context_required = !current.active_image_extent ||
        (!bank0.bank_0_crc && state_status == State::ReadStatus::Found && State::phase(state) == State::kPhaseFailedMax);
    OtaBoardOriginalSnapshotProvider original(state_, floor_, running_, qualified_);
    if (original_context_required) {
      OtaBoardOriginalImageSnapshot snapshot;
      OtaBoardOriginalSnapshotProvider::Context context;
      if (!original.read(snapshot, context) ||
          memcmp(snapshot.running.settings, before.settings, sizeof(before.settings)) ||
          snapshot.running.image != before.image || snapshot.running.capacity != before.capacity)
        return Result::TooLate;
      current = snapshot.image;
    } else {
      current.active_image_extent = (current.active_image_extent + 3u) & ~uint32_t(3);
      if (current.active_image_extent > before.capacity) return Result::TooLate;
      Bridge::computeFreshHash(before.image, current.active_image_extent, current.active_image_hash_sha256);
    }

    uint8_t records[2][Command::kRecordBytes];
    bool valid[2] = {}, matches[2] = {}, floor_refusal[2] = {}, completed_rollback[2] = {};
    bool consumed_unbound = false;
    int newest = -1;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      const uint32_t offset = slot * command_.eraseUnitBytes();
      if (!::ota::platform::isOk(command_.read(offset, records[slot], Command::kRecordBytes)))
        return Result::IoError;
      valid[slot] = Command::isValidRecord(records[slot], Command::kRecordBytes);
      if (!valid[slot]) {
        bool blank = false;
        if (!scan(command_, offset, command_.eraseUnitBytes(), blank)) return Result::IoError;
        if (!blank) return Result::TooLate;
        continue;
      }
      if (!scan(command_, offset, command_.eraseUnitBytes(), ignored)) return Result::IoError;
      meshcore::ota::protocol::OtaDescriptor d;
      if (!authentic(Command::wireDescriptorOf(records[slot]), Command::signatureOf(records[slot]),
                     Command::admittedSignerKeyOf(records[slot]), d)) return Result::TooLate;
      matches[slot] = Command::transactionNonceOf(records[slot]) == expected.transactionNonce &&
          !memcmp(Command::wireDescriptorOf(records[slot]), candidate.canonical, 59) &&
          !memcmp(Command::signatureOf(records[slot]), candidate.signature, 64) &&
          !memcmp(Command::admittedSignerKeyOf(records[slot]), candidate.ownerPublicKey, 32);
      if (newest < 0 || commandSequenceNewer(Command::sequenceOf(records[slot]), Command::sequenceOf(records[newest])))
        newest = slot;
      floor_refusal[slot] = d.securityCounter <= floor;
      completed_rollback[slot] = state_status == State::ReadStatus::Found &&
          State::phase(state) == State::kPhaseFailedMax && before.settingsTailErased &&
          State::transactionNonce(state) == Command::transactionNonceOf(records[slot]) &&
          State::candidateCounter(state) == d.securityCounter &&
          !memcmp(State::candidateHashSha256(state), d.sha256, 32) &&
          State::activeImageExtent(state) == current.active_image_extent &&
          !memcmp(state + 76, current.active_image_hash_sha256, 32);
      if (!matches[slot] && !floor_refusal[slot]) consumed_unbound = true;
    }
    const bool have_match = matches[0] || matches[1];
    if (candidate.phase == Store::Phase::Committed && !have_match) return Result::TooLate;
    // Actual cancellation cannot expose any unbound sibling above the protected floor.
    if (have_match && consumed_unbound) return Result::TooLate;
    if (have_match && (newest < 0 || !matches[newest] || candidate.receivedBlocks != candidate.totalBlocks))
      return Result::TooLate;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      if (!valid[slot]) continue;
      if (!matches[slot] && !floor_refusal[slot]) {
        // Without erasing either slot, the loader keeps selecting the proven consumed newest command.
        if (!completed_rollback[slot] &&
            (have_match || newest < 0 || !completed_rollback[newest] ||
             !commandSequenceNewer(Command::sequenceOf(records[newest]), Command::sequenceOf(records[slot]))))
          return Result::TooLate;
        continue;
      }
      const bool refused_now = floor_refusal[slot] || !before.settingsTailErased ||
          Command::activeImageExtentOf(records[slot]) != current.active_image_extent ||
          memcmp(Command::activeImageHashOf(records[slot]), current.active_image_hash_sha256, 32);
      if (!refused_now) {
        // Only this exactly bound candidate may use a fresh QSPI hash refusal.
        if (!matches[slot]) return Result::TooLate;
        uint8_t digest[32];
        if (!hashCandidate(candidate.exactSizeBytes, digest)) return Result::IoError;
        if (!memcmp(digest, descriptor.sha256, 32)) return Result::TooLate;
      }
    }

    uint8_t latest_state[State::kRecordBytes] = {};
    uint32_t latest_floor = 0;
    if (State::readNewestWithStatus(state_, latest_state) != state_status ||
        memcmp(state, latest_state, sizeof(state)) ||
        !::ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(floor_, latest_floor) ||
        latest_floor != floor || !running_.read(after)) return Result::IoError;
    auto current_after = Bridge::resolve(bank0, after.image, after.capacity);
    if (original_context_required) {
      OtaBoardOriginalImageSnapshot snapshot;
      OtaBoardOriginalSnapshotProvider::Context context;
      if (!original.read(snapshot, context) ||
          memcmp(snapshot.running.settings, after.settings, sizeof(after.settings)) ||
          snapshot.running.image != after.image || snapshot.running.capacity != after.capacity)
        return Result::TooLate;
      current_after = snapshot.image;
    } else if (current_after.active_image_extent) {
      current_after.active_image_extent = (current_after.active_image_extent + 3u) & ~uint32_t(3);
      if (current_after.active_image_extent > after.capacity) return Result::TooLate;
      Bridge::computeFreshHash(after.image, current_after.active_image_extent, current_after.active_image_hash_sha256);
    }
    if (memcmp(before.settings, after.settings, sizeof(before.settings)) ||
        before.image != after.image || before.capacity != after.capacity ||
        before.settingsTailErased != after.settingsTailErased ||
        current_after.active_image_extent != current.active_image_extent ||
        memcmp(current_after.active_image_hash_sha256, current.active_image_hash_sha256, 32)) return Result::TooLate;
    uint8_t latest_state_digest[32];
    const auto rechecked_state = inspectStateWindows(latest_state, state_status, expected.transactionNonce,
                                                     latest_state_digest);
    if (rechecked_state != Result::Ok) return rechecked_state;
    if (memcmp(state_digest, latest_state_digest, sizeof(state_digest))) return Result::TooLate;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      uint8_t reread[Command::kRecordBytes];
      if (!::ota::platform::isOk(command_.read(slot * command_.eraseUnitBytes(), reread, sizeof(reread))))
        return Result::IoError;
      if (memcmp(reread, records[slot], sizeof(reread))) return Result::TooLate;
    }
    if (!cancel || !have_match) return Result::Ok;
    if (candidate.phase != Store::Phase::Aborted) return Result::TooLate;
    // Remove an older duplicate first: no reset may resurrect an admissible sibling command.
    for (int pass = 0; pass < 2; ++pass) {
      const uint32_t slot = pass == 0 ? 1u - uint32_t(newest) : uint32_t(newest);
      if (!matches[slot]) continue;
      if (!::ota::platform::isOk(command_.eraseSector(slot * command_.eraseUnitBytes()))) return Result::IoError;
      bool blank = false;
      if (!scan(command_, slot * command_.eraseUnitBytes(), command_.eraseUnitBytes(), blank) || !blank)
        return Result::IoError;
    }
    return Result::Ok;
  }

private:
  static bool commandSequenceNewer(uint32_t next, uint32_t previous) {
    const uint32_t difference = next - previous;
    return difference != 0 && difference < 0x80000000u;
  }
  Result inspectStateWindows(const uint8_t newest[State::kRecordBytes], State::ReadStatus status,
                             uint64_t nonce, uint8_t digest[32]) const {
    return inspectOtaBoardStateWindows(state_, newest, status, nonce, digest);
  }
  static uint32_t le32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
  }
  bool authentic(const uint8_t canonical[59], const uint8_t signature[64], const uint8_t owner[32],
                 meshcore::ota::protocol::OtaDescriptor& d) const {
    return verifyOtaBoardNrfManifest(canonical, signature, owner, signatures_, target_, role_, image_.sizeBytes(), d);
  }
  static bool scan(const ::ota::platform::FlashRegion& region, uint32_t offset, uint32_t size, bool& blank) {
    uint8_t bytes[256];
    blank = true;
    for (uint32_t done = 0; done < size;) {
      const uint32_t n = size - done < sizeof(bytes) ? size - done : sizeof(bytes);
      if (!::ota::platform::isOk(region.read(offset + done, bytes, n))) return false;
      for (uint32_t i = 0; i < n; ++i) if (bytes[i] != 0xff) blank = false;
      done += n;
    }
    return true;
  }
  bool hashCandidate(uint32_t size, uint8_t out[32]) const {
    uint8_t bytes[256];
    ::ota::trust::Sha256 hash;
    for (uint32_t done = 0; done < size;) {
      const uint32_t n = size - done < sizeof(bytes) ? size - done : sizeof(bytes);
      if (!::ota::platform::isOk(image_.read(done, bytes, n))) return false;
      hash.update(bytes, n);
      done += n;
    }
    hash.finish(out);
    return true;
  }
  ::ota::platform::FlashRegion& command_;
  ::ota::platform::FlashRegion& state_;
  ::ota::platform::FlashRegion& floor_;
  ::ota::platform::FlashRegion& image_;
  const ::ota::trust::SignatureVerifier& signatures_;
  const IOtaNrf52RunningContext& running_;
  const bool& qualified_;
  uint32_t target_, role_;
};

// Three-way classification of the boot-info marker check: `Normal` is
// reserved for a FUTURE, separately signed "CertifyExistingBaseline"
// evidence chain -- NOT merely
// a blank/erased marker, and NOT merely `!isTrialActive()`. Until that
// authority is wired in (a separate owner's responsibility), this
// function NEVER produces Normal: a genuinely blank/erased marker
// (`BlankUncertifiedStock`) is an uncertified stock board and stays
// Unknown -- never installation authority. Ordinary stock writes need the
// separate fresh SDK/image and no-install-intent proof below. `Qualified` means a
// valid, fully-matching marker is present (trial-boot concept applies;
// consult the confirmer). `Unknown` also covers every other case -- a
// non-blank record that fails validation (corruption/torn write), OR a
// validly-formed record whose board/role/capability/algorithm does NOT
// match this build's expectations (a real bootloader marker is present,
// just not the one we expect) -- and MUST be treated the same as a
// genuine read failure: never silently assumed to be "no trial concept,
// safe to run destructive legacy behaviour".
enum class OtaBoardQualificationStatus { Normal, Qualified, Unknown };

// Why a given Unknown (or Qualified) classification was produced --
// purely diagnostic (e.g. for the OTA status serial frame), never itself
// a basis for any permissive decision.
enum class OtaBoardQualificationReason {
  QualifiedMatch,          // status == Qualified: real, matching marker.
  BlankUncertifiedStock,   // status == Unknown: genuinely blank/erased marker.
  CorruptMarker,           // status == Unknown: non-blank but invalid (torn/corrupt).
  RoleOrCapabilityMismatch // status == Unknown: valid marker, wrong board/role/capability/algorithm.
};


// Result of checking the boot-info/capability marker (bootloader/xiao_
// nrf52840_ota/include/xiao_ota_boot_info.h) against a specific board's
// expected identity. This is the ONLY authoritative source of "is a
// qualified MeshCore custom bootloader actually present" -- board/JEDEC
// identity, compiled feature flags, or backendAvailable() must never be
// used as a substitute (per boot-Hydra's explicit fail-closed contract).
struct OtaBoardBootQualification {
  OtaBoardQualificationStatus status = OtaBoardQualificationStatus::Unknown;
  OtaBoardQualificationReason reason = OtaBoardQualificationReason::BlankUncertifiedStock;
  ::ota::storage::XiaoOtaBootInfoReader::Info info;
  // Back-compat convenience: true iff status == Qualified. Existing call
  // sites that only ever cared about "is the durable install-capable
  // path allowed" (never "is legacy destructive behaviour safe") keep
  // working unchanged against this field.
  bool qualified = false;
};

// Pure, hardware-independent mapping from an already-obtained
// RecordStatus/Info to the OtaBoardQualificationStatus/Reason contract
// above -- extracted so native host tests can drive every branch
// (Blank/Corrupt/mismatched/matching) directly with synthetic values,
// since XiaoOtaBootInfoReader::classifyCurrent() itself is hardware-
// bound (reads a fixed memory-mapped address, only ever Corrupt
// off-target). resolveOtaBoardBootQualification() below is simply this
// function applied to the real classifyCurrent() result.
inline OtaBoardBootQualification resolveOtaBoardBootQualificationFromRecordStatus(
    ::ota::storage::XiaoOtaBootInfoReader::RecordStatus record_status,
    const ::ota::storage::XiaoOtaBootInfoReader::Info& info, uint32_t expected_target_id,
    uint32_t expected_role_id, uint32_t expected_capability_flags) {
  constexpr uint16_t kExpectedAlgorithmIdEd25519 = 1u;
  OtaBoardBootQualification result;
  if (record_status == ::ota::storage::XiaoOtaBootInfoReader::RecordStatus::Blank) {
    // Genuinely blank/erased marker: an uncertified stock/never-flashed
    // board. NOT, by itself, sufficient for a positive Normal
    // classification. Stock ordinary-write permission is a separate
    // runtime proof, never a Normal marker or install qualification.
    // Trial/reboot machinery only activates through Qualified below.
    result.status = OtaBoardQualificationStatus::Unknown;
    result.reason = OtaBoardQualificationReason::BlankUncertifiedStock;
    return result;
  }
  if (record_status == ::ota::storage::XiaoOtaBootInfoReader::RecordStatus::Corrupt) {
    result.status = OtaBoardQualificationStatus::Unknown;
    result.reason = OtaBoardQualificationReason::CorruptMarker;
    return result;
  }
  // Found: a genuinely valid (magic/format/CRC) marker is present.
  if (info.boardTargetId == expected_target_id && info.roleId == expected_role_id &&
      (info.capabilityFlags & expected_capability_flags) == expected_capability_flags &&
      info.algorithmId == kExpectedAlgorithmIdEd25519) {
    result.status = OtaBoardQualificationStatus::Qualified;
    result.reason = OtaBoardQualificationReason::QualifiedMatch;
    result.qualified = true;
    result.info = info;
    return result;
  }
  // A real, validly-formed bootloader marker is present, but it doesn't
  // match what THIS build expects (wrong board/role/capability, or an
  // algorithm we can't verify) -- ambiguous, must fail closed rather than
  // fall back to "no trial concept".
  result.status = OtaBoardQualificationStatus::Unknown;
  result.reason = OtaBoardQualificationReason::RoleOrCapabilityMismatch;
  result.info = info;
  return result;
}

// Ordinary stock-app writes are not installation, formatting or identity-generation authority.
class OtaBoardStockBootPreflight {
public:
  enum class Result {
    Healthy, NotStock, InvalidRunning, InstallJournalPresent, InvalidCache, IoError, Changed, CacheNeedsReset
  };
  struct Diagnostic {
    OtaBoardQualificationReason marker = OtaBoardQualificationReason::BlankUncertifiedStock;
    const char* proof = "not-run";
    bool sdkRead = false, tailErased = false, crcKnown = false;
    uint16_t bank0 = 0, bank1 = 0, storedCrc = 0, computedCrc = 0;
    uint32_t size = 0, journalOffset = UINT32_MAX;
  };

  static Result check(const OtaBoardBootQualification& qualification, const IOtaNrf52RunningContext& running,
                      ::ota::platform::FlashRegion& journal, Diagnostic* diagnostic = nullptr) {
    if (diagnostic) { *diagnostic = Diagnostic(); diagnostic->marker = qualification.reason; }
    const auto finish = [&](Result result, const char* proof) {
      if (diagnostic) diagnostic->proof = proof;
      return result;
    };
    if (qualification.status != OtaBoardQualificationStatus::Unknown || qualification.qualified ||
        qualification.reason != OtaBoardQualificationReason::BlankUncertifiedStock)
      return finish(Result::NotStock, "marker");
    OtaNrf52RunningContext before, after;
    if (!running.read(before)) return finish(Result::IoError, "sdk-read");
    using Bridge = ::ota::storage::XiaoOtaActiveExtentBridge;
    const auto bank = Bridge::decodeBank0FromRaw28Bytes(before.settings);
    const uint16_t bank1 = uint16_t(before.settings[4]) | (uint16_t(before.settings[5]) << 8);
    if (diagnostic) {
      diagnostic->sdkRead = true;
      diagnostic->bank0 = bank.bank_0;
      diagnostic->bank1 = bank1;
      diagnostic->storedCrc = bank.bank_0_crc;
      diagnostic->size = bank.bank_0_size;
      diagnostic->tailErased = before.settingsTailErased;
    }
    if (!before.settingsTailErased) return finish(Result::InvalidRunning, "sdk-tail");
    if (bank1 != 0xfe && bank1 != 0xff) return finish(Result::InvalidRunning, "sdk-pending-bank");
    if (bank.bank_0 != ::ota::storage::kBankValidApp) return finish(Result::InvalidRunning, "sdk-bank0");
    if (!before.image || bank.bank_0_size < 8 || bank.bank_0_size > before.capacity ||
        bank.bank_0_size > ::ota::storage::kXiaoOtaAppInstallMaxSize ||
        bank.bank_0_size > meshcore::ota::runtime::kOtaMaxImageBytes)
      return finish(Result::InvalidRunning, "sdk-size");
    if (blank(before.image, 8)) return finish(Result::InvalidRunning, "sdk-vector");
    const uint16_t computed_crc = Bridge::crc16Compute(before.image, bank.bank_0_size);
    if (diagnostic) { diagnostic->computedCrc = computed_crc; diagnostic->crcKnown = true; }
    // Vendor stock DFU stores zero to disable its optional CRC; qualified paths retain the strict bridge.
    if (bank.bank_0_crc != 0 && computed_crc != bank.bank_0_crc)
      return finish(Result::InvalidRunning, "sdk-crc");
    uint8_t image_hash[32], rechecked_image_hash[32];
    Bridge::computeFreshHash(before.image, bank.bank_0_size, image_hash);
    uint8_t digest[32], rechecked[32];
    auto result = inspectJournal(journal, digest, diagnostic);
    if (result != Result::Healthy)
      return finish(result, result == Result::InstallJournalPresent ? "install-journal" : "journal-read");
    if (!running.read(after)) return finish(Result::IoError, "sdk-recheck-read");
    if (memcmp(before.settings, after.settings, sizeof(before.settings)) || before.image != after.image ||
        before.capacity != after.capacity || before.settingsTailErased != after.settingsTailErased)
      return finish(Result::Changed, "sdk-changed");
    const uint16_t rechecked_crc = Bridge::crc16Compute(after.image, bank.bank_0_size);
    Bridge::computeFreshHash(after.image, bank.bank_0_size, rechecked_image_hash);
    if (computed_crc != rechecked_crc || memcmp(image_hash, rechecked_image_hash, sizeof(image_hash)))
      return finish(Result::Changed, "sdk-changed");
    result = inspectJournal(journal, rechecked, diagnostic);
    if (result != Result::Healthy)
      return finish(result, result == Result::InstallJournalPresent ? "install-journal" : "journal-recheck-read");
    return memcmp(digest, rechecked, sizeof(digest)) ? finish(Result::Changed, "journal-changed") :
                                                    finish(Result::Healthy, "healthy");
  }

  static void formatDiagnostic(char* out, size_t size, const Diagnostic& diagnostic) {
    const char* marker = diagnostic.marker == OtaBoardQualificationReason::BlankUncertifiedStock ? "blank" :
                         diagnostic.marker == OtaBoardQualificationReason::CorruptMarker ? "corrupt" :
                         diagnostic.marker == OtaBoardQualificationReason::QualifiedMatch ? "qualified" : "mismatch";
    if (!diagnostic.sdkRead) {
      snprintf(out, size, "marker=%s proof=%s sdk=unread", marker, diagnostic.proof);
      return;
    }
    char crc[5] = "?", offset[9] = "?";
    if (diagnostic.crcKnown) snprintf(crc, sizeof(crc), "%04X", unsigned(diagnostic.computedCrc));
    if (diagnostic.journalOffset != UINT32_MAX)
      snprintf(offset, sizeof(offset), "%08lX", static_cast<unsigned long>(diagnostic.journalOffset));
    snprintf(out, size, "marker=%s proof=%s off=%s bank0=%X bank1=%X size=%lu crc=%04X/%s tail=%u",
             marker, diagnostic.proof, offset, unsigned(diagnostic.bank0), unsigned(diagnostic.bank1),
             static_cast<unsigned long>(diagnostic.size), unsigned(diagnostic.storedCrc), crc,
             unsigned(diagnostic.tailErased));
  }

  // Stock boot never consumes cache records; their integrity cannot revoke ordinary-write proof.
  static Result checkCache(::ota::platform::FlashRegion& records, const ::ota::trust::SignatureVerifier& signatures) {
    uint8_t digest[32], rechecked[32];
    const auto result = inspectCache(records, signatures, digest);
    if (!cacheAttachAllowed(result)) return result;
    const auto after = inspectCache(records, signatures, rechecked);
    if (!cacheAttachAllowed(after)) return after;
    return result != after || memcmp(digest, rechecked, sizeof(digest)) ? Result::Changed : result;
  }

  static bool cacheAttachAllowed(Result result) {
    return result == Result::Healthy || result == Result::CacheNeedsReset;
  }

  static const char* reason(Result result) {
    switch (result) {
      case Result::Healthy: return "verified stock boot";
      case Result::NotStock: return "stock marker unproven";
      case Result::InvalidRunning: return "stock SDK/image unproven";
      case Result::InstallJournalPresent: return "install journal present";
      case Result::InvalidCache: return "cache metadata unproven";
      case Result::IoError: return "stock preflight read error";
      case Result::Changed: return "stock proof changed";
      case Result::CacheNeedsReset: return "cache needs explicit retry/reupload";
    }
    return "stock proof unavailable";
  }

private:
  using Store = ::ota::storage::OtaCandidateStore;
  static uint32_t le32(const uint8_t* bytes) {
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) | (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
  }
  static bool blank(const uint8_t* bytes, size_t count) {
    for (size_t i = 0; i < count; ++i) if (bytes[i] != 0xff) return false;
    return true;
  }
  static bool sameCacheContentBinding(const uint8_t* left, const uint8_t* right) {
    // Retry/ABORT may advance session and attempt without changing the owned image.
    return !memcmp(left, right, 10) && !memcmp(left + 16, right + 16, 155);
  }
  static Result inspectJournal(::ota::platform::FlashRegion& journal, uint8_t digest[32], Diagnostic* diagnostic) {
    if (!journal.isValid() || journal.sizeBytes() != 4 * Store::kExpectedRegionBytes ||
        journal.eraseUnitBytes() != Store::kSectorBytes) return Result::IoError;
    ::ota::trust::Sha256 hash;
    uint8_t bytes[Store::kRecordBytes];
    for (uint32_t offset = 0; offset < journal.sizeBytes(); offset += sizeof(bytes)) {
      if (!::ota::platform::isOk(journal.read(offset, bytes, sizeof(bytes)))) {
        if (diagnostic) diagnostic->journalOffset = offset;
        return Result::IoError;
      }
      if (!blank(bytes, sizeof(bytes))) {
        if (diagnostic) for (size_t i = 0; i < sizeof(bytes); ++i) {
          if (bytes[i] != 0xff) { diagnostic->journalOffset = offset + i; break; }
        }
        return Result::InstallJournalPresent;
      }
      hash.update(bytes, sizeof(bytes));
    }
    hash.finish(digest);
    return Result::Healthy;
  }
  static Result inspectCache(::ota::platform::FlashRegion& records,
                             const ::ota::trust::SignatureVerifier& signatures, uint8_t digest[32]) {
    if (!records.isValid() || records.sizeBytes() != Store::kExpectedRegionBytes ||
        records.eraseUnitBytes() != Store::kSectorBytes) return Result::IoError;
    ::ota::trust::Sha256 hash;
    uint8_t bytes[Store::kRecordBytes], latest_binding[171], torn_binding[171];
    bool found_cache = false, found_blank = false, found_torn = false, needs_reset = false;
    uint32_t sequence = 0, total_blocks = 0, received = 0;
    uint32_t sequences[Store::kRecordSlots] = {}, valid_count = 0;
    uint8_t latest_phase = 0;
    for (uint32_t offset = 0; offset < Store::kSectorBytes; offset += sizeof(bytes)) {
      if (!::ota::platform::isOk(records.read(offset, bytes, sizeof(bytes)))) return Result::IoError;
      hash.update(bytes, sizeof(bytes));
      if (blank(bytes, sizeof(bytes))) { found_blank = true; continue; }
      // Match readSlot(): ignored torn bodies cannot supply ownership or phase.
      if (le32(bytes) != Store::kMagic ||
          le32(bytes + 184) != ::ota::storage::Crc32::computeFinalized(bytes, 184)) {
        needs_reset = true;
        continue;
      }
      const uint8_t phase = bytes[12] & 0x7f;
      if (bytes[4] != Store::kVersion || bytes[5] ||
          bytes[6] != (Store::kRecordBytes & 0xff) || bytes[7] != (Store::kRecordBytes >> 8) ||
          !(bytes[12] & 0x80) || phase > uint8_t(Store::Phase::Failed) || phase == uint8_t(Store::Phase::Committed) ||
          !le32(bytes + 8) || (le32(bytes + 188) & Store::kCommitMarker) != Store::kCommitMarker ||
          !blank(bytes + 192, sizeof(bytes) - 192)) return Result::InvalidCache;
      meshcore::ota::protocol::OtaDescriptor descriptor;
      if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(bytes + 29, 59, descriptor) !=
              meshcore::ota::protocol::OtaDescriptorCodecResult::Ok ||
          !descriptor.exactSizeBytes || descriptor.exactSizeBytes > meshcore::ota::runtime::kOtaMaxImageBytes ||
          descriptor.formatId != 1 || descriptor.algorithmId != 1 || !descriptor.keyId || !descriptor.appAddress ||
          le32(bytes + 15) != descriptor.exactSizeBytes ||
          (uint16_t(bytes[13]) | (uint16_t(bytes[14]) << 8)) !=
              (descriptor.exactSizeBytes + kOtaBlockMaxDataBytes - 1) / kOtaBlockMaxDataBytes ||
          !signatures.verify(bytes + 120, 64, bytes + 29, 59, bytes + 88, 32)) return Result::InvalidCache;
      // Only a complete authenticated body can explain an unfinished marker.
      // The store ignores this slot; never project its phase or ownership.
      if (le32(bytes + 188) != Store::kCommitMarker) {
        if (found_torn && !sameCacheContentBinding(torn_binding, bytes + 13)) return Result::InvalidCache;
        memcpy(torn_binding, bytes + 13, sizeof(torn_binding));
        found_torn = true;
        needs_reset = true;
        continue;
      }
      const uint32_t next_sequence = le32(bytes + 8);
      for (uint32_t i = 0; i < valid_count; ++i)
        if (sequences[i] == next_sequence) return Result::InvalidCache;
      sequences[valid_count++] = next_sequence;
      // A partial erase can remove early slots while leaving a valid owned suffix.
      if (found_blank || next_sequence < sequence) needs_reset = true;
      if (!found_cache || next_sequence > sequence) {
        sequence = next_sequence;
        total_blocks = uint16_t(bytes[13]) | (uint16_t(bytes[14]) << 8);
        latest_phase = phase;
        memcpy(latest_binding, bytes + 13, sizeof(latest_binding));
      }
      found_cache = true;
    }
    if (found_torn && found_cache && !sameCacheContentBinding(latest_binding, torn_binding))
      return Result::InvalidCache;
    for (uint32_t offset = Store::kBitmapSectorOffset; offset < records.sizeBytes(); offset += sizeof(bytes)) {
      if (!::ota::platform::isOk(records.read(offset, bytes, sizeof(bytes)))) return Result::IoError;
      hash.update(bytes, sizeof(bytes));
      for (uint32_t i = 0; i < sizeof(bytes); ++i) for (uint8_t bit = 0; bit < 8; ++bit) {
        if (bytes[i] & (1u << bit)) continue;
        if (!found_cache) { needs_reset = true; continue; }
        if ((offset - Store::kBitmapSectorOffset + i) * 8 + bit >= total_blocks) return Result::InvalidCache;
        ++received;
      }
    }
    if (found_cache && (latest_phase == uint8_t(Store::Phase::Verifying) || latest_phase == uint8_t(Store::Phase::Ready)) &&
        received != total_blocks) return Result::InvalidCache;
    hash.finish(digest);
    return needs_reset ? Result::CacheNeedsReset : Result::Healthy;
  }
};

inline void formatOtaOrdinaryWriteDiagnostic(char* out, size_t size, bool writes_blocked, const char* detail) {
  snprintf(out, size, "writes=%s %s", writes_blocked ? "blocked" : "allowed",
           detail ? detail : "proof=backend-unavailable");
}

inline size_t encodeOtaOrdinaryWriteDiagnostic(uint8_t* out, size_t size, uint8_t response_code,
                                             bool writes_blocked, const char* detail) {
  if (!out || size < 2) return 0;
  out[0] = response_code;
  formatOtaOrdinaryWriteDiagnostic(reinterpret_cast<char*>(out + 1), size - 1, writes_blocked, detail);
  return 1 + strlen(reinterpret_cast<char*>(out + 1));
}

// Fail-closed boot-marker qualification check, shared by both backends.
// Only a struct that passes XiaoOtaBootInfoReader's magic/format/CRC
// validation is trusted at all, and even then, only when its
// board_target_id/role/capability genuinely match this build's
// expectations AND algorithm_id is the one value this firmware's
// SignatureVerifier actually implements (Ed25519, id 1) -- never board/
// JEDEC identity or a compiled flag alone. All-0xFF (stock/unmodified
// Adafruit bootloader) is the expected, common, non-error case here, not
// corruption -- see XiaoOtaBootInfoReader::RecordStatus's Blank-vs-Corrupt
// distinction, which this function surfaces via OtaBoardQualificationStatus
// rather than collapsing it into a single boolean.
inline OtaBoardBootQualification resolveOtaBoardBootQualification(uint32_t expected_target_id,
                                                                  uint32_t expected_role_id,
                                                                  uint32_t expected_capability_flags) {
  ::ota::storage::XiaoOtaBootInfoReader::Info info;
  const auto record_status = ::ota::storage::XiaoOtaBootInfoReader::classifyCurrent(info);
  return resolveOtaBoardBootQualificationFromRecordStatus(record_status, info, expected_target_id,
                                                          expected_role_id, expected_capability_flags);
}

// Typed, positively-evidenced startup classification -- DISTINCT from
// (and strictly narrower than) both OtaBoardQualificationStatus (is a
// qualified custom-bootloader marker present at all) and
// OtaBoardTrialBootHealthConfirmer::isTrialActive() (is a TRIAL_BOOT
// phase, or ambiguous state, currently unresolved). Neither of those
// alone is sufficient evidence to permit ordinary destructive userdata
// behaviour (identity generation, format, migrations): a qualified
// marker with a genuinely BLANK state region (no install ever attempted)
// or a Found record whose phase is anything other than kPhaseConfirmed
// (EMPTY/REQUESTED/BACKUP_*/INSTALL_COPYING/ROLLBACK_COPYING/FAILED) is
// ambiguous -- "not currently an active trial" is NOT the same as
// "positively proven safe" -- and must stay Unknown (read-only local
// maintenance for the whole boot), never silently promoted to Normal.
// IMPORTANT: a Found record whose phase is kPhaseConfirmed is NECESSARY
// but NOT SUFFICIENT for Normal. The bootloader phase byte alone only
// proves that the bootloader validated this app's durable confirmation
// record against ITS OWN state record on a prior boot -- it does NOT
// bind that evidence to the CURRENTLY RUNNING image: a USB reflash (or
// any other out-of-band image replacement) after CONFIRMED was written
// leaves the phase byte untouched while the running image/SDK/CRC/
// SHA-256/source-signature/role/floor/sidecar metadata may now disagree
// entirely with what was actually confirmed. Therefore Normal additionally
// requires `has_verified_fresh_baseline_proof`. The original-snapshot
// provider supplies fresh SDK/hash/floor/state and no-active-intent proof;
// phase alone remains Unknown (ConfirmedPendingFreshVerification).
// FAILED (phase 8) alone is explicitly NOT treated as a verified
// rollback: it only records that the bootloader gave up on the trial,
// not that a rollback to a known-good baseline was itself verified
// complete. The separate original-startup mapping accepts only an exact
// saved-SDK/backup-SHA restoration or an existing image-bound factory floor0.
enum class OtaBoardStartupDecisionStatus { Normal, Trial, Unknown };

enum class OtaBoardStartupDecisionReason {
  ConfirmedInstallEvidence,  // Normal: Found + phase == kPhaseConfirmed AND fresh baseline proof supplied.
  ConfirmedPendingFreshVerification, // Unknown: Found + phase == kPhaseConfirmed, but NO fresh
                             // SDK/CRC/SHA/signature/role binding proof was supplied for the
                             // CURRENTLY RUNNING image -- phase alone never promotes to Normal.
  ActiveTrialBoot,           // Trial: Found + phase == kPhaseTrialBoot.
  StateUnreadable,           // Trial (fails closed): state read Unknown or Corrupt.
  NotQualified,              // Unknown: board itself is not Qualified (see OtaBoardQualificationStatus).
  NoInstallHistory,          // Unknown: Qualified, but state region is genuinely Blank (never installed).
  IncompleteOrAmbiguousPhase,// Unknown: Qualified, Found, but phase is neither TrialBoot nor Confirmed
                             // (includes FAILED -- "FAILED alone is not rollback").
  FactoryOriginalEvidence,
  RestoredOriginalEvidence,
};

struct OtaBoardStartupDecision {
  OtaBoardStartupDecisionStatus status = OtaBoardStartupDecisionStatus::Unknown;
  OtaBoardStartupDecisionReason reason = OtaBoardStartupDecisionReason::NotQualified;
};

// Pure, hardware-independent mapping -- native-testable directly with
// synthetic (qualified, ReadStatus, phase, has_verified_fresh_baseline_proof)
// inputs, mirroring resolveOtaBoardBootQualificationFromRecordStatus()'s
// pattern. `has_verified_fresh_baseline_proof` defaults to false and is
// supplied only by the original provider's ordinary-write proof. Passing true from
// anywhere without a genuine binding to the running image would itself
// be a fabricated-Normal bug in the CALLER, not in this function.
inline OtaBoardStartupDecision resolveOtaBoardStartupDecision(
    bool qualified, ::ota::storage::XiaoOtaStateReader::ReadStatus state_status, uint32_t state_phase,
    bool has_verified_fresh_baseline_proof = false) {
  OtaBoardStartupDecision result;
  if (!qualified) {
    result.status = OtaBoardStartupDecisionStatus::Unknown;
    result.reason = OtaBoardStartupDecisionReason::NotQualified;
    return result;
  }
  if (state_status == ::ota::storage::XiaoOtaStateReader::ReadStatus::Unknown ||
      state_status == ::ota::storage::XiaoOtaStateReader::ReadStatus::Corrupt) {
    result.status = OtaBoardStartupDecisionStatus::Trial;
    result.reason = OtaBoardStartupDecisionReason::StateUnreadable;
    return result;
  }
  if (state_status == ::ota::storage::XiaoOtaStateReader::ReadStatus::Blank) {
    result.status = OtaBoardStartupDecisionStatus::Unknown;
    result.reason = OtaBoardStartupDecisionReason::NoInstallHistory;
    return result;
  }
  // Found.
  if (state_phase == ::ota::storage::XiaoOtaStateReader::kPhaseTrialBoot) {
    result.status = OtaBoardStartupDecisionStatus::Trial;
    result.reason = OtaBoardStartupDecisionReason::ActiveTrialBoot;
    return result;
  }
  if (state_phase == ::ota::storage::XiaoOtaStateReader::kPhaseConfirmed) {
    if (has_verified_fresh_baseline_proof) {
      result.status = OtaBoardStartupDecisionStatus::Normal;
      result.reason = OtaBoardStartupDecisionReason::ConfirmedInstallEvidence;
    } else {
      result.status = OtaBoardStartupDecisionStatus::Unknown;
      result.reason = OtaBoardStartupDecisionReason::ConfirmedPendingFreshVerification;
    }
    return result;
  }
  result.status = OtaBoardStartupDecisionStatus::Unknown;
  result.reason = OtaBoardStartupDecisionReason::IncompleteOrAmbiguousPhase;
  return result;
}

inline OtaBoardStartupDecision resolveOtaBoardOriginalStartupDecision(
    bool qualified, ::ota::storage::XiaoOtaStateReader::ReadStatus status, uint32_t phase,
    bool verified_original_ordinary_writes) {
  auto result = resolveOtaBoardStartupDecision(qualified, status, phase, verified_original_ordinary_writes);
  if (!qualified || !verified_original_ordinary_writes) return result;
  if (status == ::ota::storage::XiaoOtaStateReader::ReadStatus::Blank) {
    result.status = OtaBoardStartupDecisionStatus::Normal;
    result.reason = OtaBoardStartupDecisionReason::FactoryOriginalEvidence;
  } else if (status == ::ota::storage::XiaoOtaStateReader::ReadStatus::Found &&
             phase == ::ota::storage::XiaoOtaStateReader::kPhaseFailedMax) {
    result.status = OtaBoardStartupDecisionStatus::Normal;
    result.reason = OtaBoardStartupDecisionReason::RestoredOriginalEvidence;
  }
  return result;
}

// Populates ALL SIX identity fields of a DeviceTrustAnchor from an
// explicit, already-resolved (target/role/capability, format/key/
// algorithm) identity -- shared by both backends specifically so that
// `expected_format_id` (a fixed protocol wire-format version, e.g.
// XIAO_OTA_DESCRIPTOR_FORMAT) can never be silently left at its zero
// default the way expected_key_id/expected_algorithm_id are ordinarily
// sourced per-call-site from a qualified marker or lab fallback. See
// DeviceTrustAnchor's own comment (ota/trust/TrustTypes.h): 0 in any of
// format/key/algorithm is a valid, explicit value, never "unset", so a
// caller that forgets one produces a fail-closed rejection of every
// legitimately signed descriptor tagged with a real (nonzero) value --
// not a security hole, but a genuine functional regression that must be
// fixed at the source, never worked around by relaxing the check itself.
inline void configureOtaTrustAnchorIdentity(::ota::trust::DeviceTrustAnchor& anchor,
                                            uint32_t expected_target_id, uint32_t expected_role_id,
                                            uint32_t supported_boot_capability_flags,
                                            uint16_t expected_format_id, uint16_t expected_key_id,
                                            uint16_t expected_algorithm_id) {
  anchor.expected_target_id = expected_target_id;
  anchor.expected_role_id = expected_role_id;
  anchor.supported_boot_capability_flags = supported_boot_capability_flags;
  anchor.expected_format_id = expected_format_id;
  anchor.expected_key_id = expected_key_id;
  anchor.expected_algorithm_id = expected_algorithm_id;
}

// Numeric baseline0 on a blank floor is diagnostic information, never
// installer permission. Production additionally verifies an original snapshot.
struct OtaBoardInstallGateResult {
  bool install_capable = false;
  uint32_t floor_value = 0;
  const char* reason = "STAGING_ONLY: floor corrupt, unreadable or not initialized";
};

inline OtaBoardInstallGateResult resolveOtaBoardInstallGate(bool qualified,
                                                            uint32_t bank0_active_image_extent,
                                                            OtaBoardFailClosedMonotonicCounter& counter) {
  OtaBoardInstallGateResult result;
  if (!qualified || bank0_active_image_extent == 0) return result;
  uint32_t floor_value = 0;
  uint32_t initialized_floor = 0;
  if (!counter.currentValue(floor_value) || !counter.initializedValue(initialized_floor) ||
      floor_value != initialized_floor) return result;
  result.install_capable = true;
  result.floor_value = floor_value;
  result.reason = "INSTALL_CAPABLE: qualified custom bootloader detected (command v3)";
  return result;
}

inline OtaBoardInstallGateResult resolveOtaBoardOriginalInstallGate(bool qualified,
    const OtaBoardOriginalSnapshotProvider& original, OtaBoardFailClosedMonotonicCounter& counter) {
  OtaBoardInstallGateResult result;
  if (!qualified) return result;
  const auto floor = original.floorInitialization();
  if (floor == OtaBoardOriginalSnapshotProvider::FloorInitialization::Blank) {
    result.reason = "STAGING_ONLY: floor not initialized";
    return result;
  }
  if (floor != OtaBoardOriginalSnapshotProvider::FloorInitialization::Initialized) return result;
  ::ota::storage::XiaoOtaActiveExtentInfo image;
  if (!original.readOriginalSnapshot(image)) {
    result.reason = "STAGING_ONLY: original SDK/hash/floor/state proof unavailable";
    return result;
  }
  return resolveOtaBoardInstallGate(qualified, image.active_image_extent, counter);
}

// Formats a compact ("REASON: detail", <=63 bytes incl. NUL) install-
// capability status line into `out` (caller-owned buffer of at least
// `out_len` bytes) so it fits comfortably inside the existing OTA status
// serial frame's <=176-byte budget alongside other fields. Truncates
// (never overflows) if `reason` is longer than `out_len - 1`.
inline void formatOtaBoardCapabilityStatus(char* out, size_t out_len, const char* reason) {
  if (out == nullptr || out_len == 0) return;
  if (reason == nullptr) reason = "";
  size_t n = strlen(reason);
  if (n > out_len - 1) n = out_len - 1;
  memcpy(out, reason, n);
  out[n] = '\0';
}

struct OtaBoardFloorDiagnostic {
  enum class Status { Present, Blank, Corrupt, ReadError, Unavailable };
  Status status = Status::Unavailable;
  uint32_t sequence = 0, counter = 0, extent = 0;
  uint8_t hash[32] = {};

  static OtaBoardFloorDiagnostic read(const ::ota::platform::FlashRegion& region) {
    using Floor = ::ota::storage::XiaoOtaFloorReader;
    OtaBoardFloorDiagnostic result;
    if (!region.isValid() || region.sizeBytes() != 2u * region.eraseUnitBytes() ||
        region.eraseUnitBytes() < Floor::kRecordBytes) return result;
    bool found = false, damaged = false;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      const uint32_t base = slot * region.eraseUnitBytes();
      uint8_t record[Floor::kRecordBytes], bytes[256];
      if (!::ota::platform::isOk(region.read(base, record, sizeof(record)))) {
        result.status = Status::ReadError;
        return result;
      }
      if (Floor::isValidRecord(record, sizeof(record))) {
        const uint32_t sequence = le32(record + 8);
        if (!found || sequence >= result.sequence) {
          result.sequence = sequence;
          result.counter = le32(record + 12);
          result.extent = le32(record + 16);
          memcpy(result.hash, record + 20, sizeof(result.hash));
        }
        found = true;
      } else {
        for (const auto byte : record) if (byte != 0xff) damaged = true;
      }
      for (uint32_t offset = sizeof(record); offset < region.eraseUnitBytes();) {
        const uint32_t n = region.eraseUnitBytes() - offset < sizeof(bytes) ?
            region.eraseUnitBytes() - offset : sizeof(bytes);
        if (!::ota::platform::isOk(region.read(base + offset, bytes, n))) {
          result.status = Status::ReadError;
          return result;
        }
        for (uint32_t i = 0; i < n; ++i) if (bytes[i] != 0xff) damaged = true;
        offset += n;
      }
    }
    result.status = damaged ? Status::Corrupt : found ? Status::Present : Status::Blank;
    return result;
  }
private:
  static uint32_t le32(const uint8_t* bytes) {
    return uint32_t(bytes[0]) | uint32_t(bytes[1]) << 8 | uint32_t(bytes[2]) << 16 | uint32_t(bytes[3]) << 24;
  }
};

static constexpr size_t kOtaBoardFloorCapabilityStatusBytes = 145;
static_assert(kOtaBoardFloorCapabilityStatusBytes + sizeof("writes=blocked ") - 1 <= 160,
              "Floor evidence must fit the existing repeater diagnostic reply");

inline void formatOtaBoardFloorCapabilityStatus(char* out, size_t size, const char* capability,
                                                const ::ota::platform::FlashRegion& floor) {
  if (!out || !size) return;
  const auto evidence = OtaBoardFloorDiagnostic::read(floor);
  using Status = OtaBoardFloorDiagnostic::Status;
  int count;
  if (evidence.status == Status::Present) {
    const char* prefix = capability && !strncmp(capability, "INSTALL_CAPABLE:", 16) ? "INSTALL_CAPABLE" :
        capability && !strncmp(capability, "CACHE_ONLY:", 11) ? "CACHE_ONLY" : "STAGING_ONLY";
    char hash[65];
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < sizeof(evidence.hash); ++i) {
      hash[2 * i] = hex[evidence.hash[i] >> 4];
      hash[2 * i + 1] = hex[evidence.hash[i] & 15];
    }
    hash[64] = '\0';
    count = snprintf(out, size, "%s: floor=present seq=%08lX ctr=%08lX ext=%08lX sha=%s io=ok", prefix,
                     static_cast<unsigned long>(evidence.sequence), static_cast<unsigned long>(evidence.counter),
                     static_cast<unsigned long>(evidence.extent), hash);
  } else {
    const bool blank = evidence.status == Status::Blank;
    const char* state = blank ? "blank" : evidence.status == Status::Corrupt ? "corrupt" :
        evidence.status == Status::ReadError ? "read-error" : "unavailable";
    const char* io = evidence.status == Status::ReadError ? "read-error" :
        evidence.status == Status::Unavailable ? "geometry" : "ok";
    count = snprintf(out, size, "STAGING_ONLY: %sfloor=%s seq=? ctr=? ext=? sha=? io=%s",
                     blank ? "floor not initialized " : "", state, io);
  }
  // A truncated hash must never look like complete commissioning evidence.
  if (count < 0 || static_cast<size_t>(count) >= size)
    snprintf(out, size, "STAGING_ONLY: floor=unavailable io=buffer");
}

// Convenience alias so callers outside ::ota::storage (backend .cpp
// files, MyMesh.cpp) can spell the outcome type without the fully
// qualified ::ota::storage:: prefix.
using OtaBoardTrialHealthOutcome = ::ota::storage::XiaoOtaTrialHealthOutcome;

// Real-hardware adapter feeding
// ::ota::storage::XiaoOtaIncrementalExtentResolver (bounded, per-tick
// extent-CRC steps -- never a single blocking whole-image CRC) into
// ::ota::storage::XiaoOtaTrialHealthMonitor's injectable
// IXiaoOtaActiveImageAccessor seam, decoupled so native tests can supply
// a synthetic in-memory image fixture instead (the real resolver reads
// fixed NRF52840_XXAA hardware addresses and fails closed off-target,
// making the real confirm path otherwise untestable off-target).
class OtaBoardRealActiveImageAccessor : public ::ota::storage::IXiaoOtaActiveImageAccessor {
public:
  ::ota::storage::XiaoOtaExtentResolutionStep stepExtentResolution(uint32_t max_bytes, const uint8_t** out_image,
                                                                   uint32_t* out_extent) override {
    return resolver_.step(max_bytes, out_image, out_extent);
  }

private:
  ::ota::storage::XiaoOtaIncrementalExtentResolver resolver_;
};

// Observes existing bootloader records and verifies the running bytes.
// It never writes a confirmation, floor, command, or lifecycle record.
class OtaBoardBootLifecycleObserver {
public:
  OtaBoardBootLifecycleObserver(::ota::platform::FlashRegion& state, ::ota::platform::FlashRegion& floor)
      : state_(state), floor_(floor), accessor_(&real_accessor_) {}
  OtaBoardBootLifecycleObserver(::ota::platform::FlashRegion& state, ::ota::platform::FlashRegion& floor,
                                ::ota::storage::IXiaoOtaActiveImageAccessor& accessor)
      : state_(state), floor_(floor), accessor_(&accessor) {}
  OtaBoardBootLifecycleObserver(::ota::platform::FlashRegion& state, ::ota::platform::FlashRegion& floor,
                                const OtaBoardOriginalSnapshotProvider& original)
      : state_(state), floor_(floor), accessor_(&real_accessor_), original_(&original) {}

  void tick(bool qualified) {
    if (!qualified || finished_) return;
    if (!loaded_) {
      loaded_ = true;
      uint8_t record[::ota::storage::XiaoOtaStateReader::kRecordBytes];
      if (::ota::storage::XiaoOtaStateReader::readNewestWithStatus(state_, record) !=
          ::ota::storage::XiaoOtaStateReader::ReadStatus::Found) { finished_ = true; return; }
      state_phase_ = ::ota::storage::XiaoOtaStateReader::phase(record);
      evidence_.transactionNonce = ::ota::storage::XiaoOtaStateReader::transactionNonce(record);
      evidence_.counter = ::ota::storage::XiaoOtaStateReader::candidateCounter(record);
      memcpy(expected_hash_, ::ota::storage::XiaoOtaStateReader::installedHashSha256(record), 32);
      if (evidence_.transactionNonce && state_phase_ == ::ota::storage::XiaoOtaStateReader::kPhaseFailedMax) {
        evidence_.phase = usb::UsbOtaPhase::Failed;
        memcpy(candidate_hash_, ::ota::storage::XiaoOtaStateReader::candidateHashSha256(record), 32);
        memcpy(expected_hash_, record + 76, 32);  // Existing boot-state backup hash.
        expected_extent_ = ::ota::storage::XiaoOtaStateReader::activeImageExtent(record);
      } else if (!evidence_.transactionNonce ||
          memcmp(expected_hash_, ::ota::storage::XiaoOtaStateReader::candidateHashSha256(record), 32)) {
        finished_ = true; return;
      }
      if (state_phase_ == ::ota::storage::XiaoOtaStateReader::kPhaseTrialBoot) {
        memcpy(evidence_.imageHash, expected_hash_, 32);
        evidence_.phase = usb::UsbOtaPhase::Trial;
        finished_ = true;
        return;
      }
      if (state_phase_ != ::ota::storage::XiaoOtaStateReader::kPhaseConfirmed &&
          state_phase_ != ::ota::storage::XiaoOtaStateReader::kPhaseFailedMax) {
        finished_ = true;
        return;
      }
    }
    if (state_phase_ == ::ota::storage::XiaoOtaStateReader::kPhaseFailedMax && original_) {
      OtaBoardOriginalImageSnapshot snapshot;
      OtaBoardOriginalSnapshotProvider::Context context;
      if (original_->read(snapshot, context) && context == OtaBoardOriginalSnapshotProvider::Context::RestoredOriginal) {
        image_ = snapshot.running.image;
        image_extent_ = offset_ = snapshot.image.active_image_extent;
        memcpy(running_hash_, snapshot.image.active_image_hash_sha256, 32);
      }
      finished_ = true;
      return;
    }
    if (!image_) {
      const auto result = accessor_->stepExtentResolution(kBytesPerTick, &image_, &image_extent_);
      if (result == ::ota::storage::XiaoOtaExtentResolutionStep::InProgress) {
        image_ = nullptr;
        image_extent_ = 0;
        return;
      }
      if (result != ::ota::storage::XiaoOtaExtentResolutionStep::Resolved || !image_ ||
          !image_extent_) { finished_ = true; return; }
    }
    const uint32_t chunk = (image_extent_ - offset_) < kBytesPerTick ? image_extent_ - offset_ : kBytesPerTick;
    hasher_.update(image_ + offset_, chunk);
    offset_ += chunk;
    if (offset_ != image_extent_) return;
    hasher_.finish(running_hash_);
    if (state_phase_ != ::ota::storage::XiaoOtaStateReader::kPhaseFailedMax) {
      memcpy(evidence_.imageHash, running_hash_, 32);
      evidence_.imageVerified = memcmp(evidence_.imageHash, expected_hash_, 32) == 0;
    }
    finished_ = true;
  }

  bool read(bool qualified, OtaBootLifecycleEvidence& out) const {
    out = OtaBootLifecycleEvidence();
    if (!qualified) return false;
    out = evidence_;
    uint8_t floor_hash[32]; uint32_t floor_extent = 0;
    uint32_t initialized_floor = 0;
    out.floorKnown = ::ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounter(floor_, initialized_floor) &&
        ::ota::storage::XiaoOtaFloorReader::readNewestConfirmedEvidenceFailClosed(floor_,
                                                                                           out.confirmedFloor,
                                                                                           floor_hash, &floor_extent) &&
        initialized_floor == out.confirmedFloor;
    if (state_phase_ == ::ota::storage::XiaoOtaStateReader::kPhaseConfirmed &&
        out.imageVerified && out.floorKnown && out.confirmedFloor == out.counter &&
        floor_extent == image_extent_ && memcmp(floor_hash, out.imageHash, 32) == 0)
      out.phase = usb::UsbOtaPhase::Installed;
    if (state_phase_ == ::ota::storage::XiaoOtaStateReader::kPhaseFailedMax && finished_ && image_ &&
        image_extent_ && offset_ == image_extent_ &&
        ((image_extent_ == expected_extent_ && !memcmp(running_hash_, expected_hash_, 32)) ||
         (out.floorKnown && out.confirmedFloor > out.counter && floor_extent == image_extent_ &&
          !memcmp(floor_hash, running_hash_, 32)))) {
      memcpy(out.imageHash, candidate_hash_, 32);
    }
    return true;
  }
  bool pending() const { return !finished_; }

private:
  static constexpr uint32_t kBytesPerTick = 4096;
  ::ota::platform::FlashRegion& state_;
  ::ota::platform::FlashRegion& floor_;
  OtaBoardRealActiveImageAccessor real_accessor_;
  ::ota::storage::IXiaoOtaActiveImageAccessor* accessor_;
  const OtaBoardOriginalSnapshotProvider* original_ = nullptr;
  ::ota::trust::Sha256 hasher_;
  OtaBootLifecycleEvidence evidence_;
  uint8_t expected_hash_[32] = {};
  uint8_t candidate_hash_[32] = {}, running_hash_[32] = {};
  const uint8_t* image_ = nullptr;
  uint32_t image_extent_ = 0, offset_ = 0, state_phase_ = 0;
  uint32_t expected_extent_ = 0;
  bool loaded_ = false, finished_ = false;
};

inline void formatOtaBootLifecycleStatus(char* out, size_t size, const OtaBootLifecycleEvidence& boot,
                                         usb::UsbOtaPhase phase, uint32_t counter) {
  char floor[12] = "unknown", image[65] = "unknown";
  if (boot.floorKnown) snprintf(floor, sizeof(floor), "%lu", (unsigned long)boot.confirmedFloor);
  if (boot.imageVerified) {
    static constexpr char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
      image[2 * i] = hex[boot.imageHash[i] >> 4];
      image[2 * i + 1] = hex[boot.imageHash[i] & 15];
    }
    image[64] = 0;
  }
  const char* boot_name = boot.phase == usb::UsbOtaPhase::Installed ? "confirmed" :
                          boot.phase == usb::UsbOtaPhase::Trial ? "trial" :
                          boot.phase == usb::UsbOtaPhase::Failed ? "failed" : "unknown";
  snprintf(out, size, "boot=%s phase=%s floor=%s counter=%lu verified=%u image=%s", boot_name,
           otaLifecyclePhaseName(phase), floor, (unsigned long)counter, boot.imageVerified ? 1 : 0, image);
}

// Thin board-facing wrapper around ::ota::storage::XiaoOtaTrialHealthMonitor
// (see that header for the full continuous-window/deadline/incremental-
// hash contract), shared by both backends' loop()-tick entry points. Owns
// the real hardware image accessor by default so backend .cpp files never
// need to reference ::ota::storage directly; native tests can instead
// inject a synthetic IXiaoOtaActiveImageAccessor via the 3-arg
// constructor to exercise the genuine positive-confirmation path off
// real hardware.
class OtaBoardTrialBootHealthConfirmer {
public:
  // `boot_epoch_ms` MUST be the genuine application boot origin, NOT a
  // fresh clock reading taken here at (lazy) construction time, and NOT
  // this object's first tick() timestamp. In production, Arduino's
  // millis() already counts from actual power-on/reset, so the correct
  // value is the constant 0 (see the backend .cpp files) -- reading
  // millis() again right before constructing this object (itself only
  // done once the flash driver is ready and the boot marker is
  // qualified, which happens well into setup(), after Serial/board/
  // radio/filesystem begin() calls) would silently discount however
  // long that earlier setup() work took from the 45s deadline budget,
  // extending it on a slow boot -- exactly the hazard this must avoid.
  // See XiaoOtaTrialHealthMonitor's own constructor doc comment for why
  // arming lazily on first tick() is likewise unsafe.
  OtaBoardTrialBootHealthConfirmer(::ota::platform::FlashRegion& state_region,
                                   ::ota::platform::FlashRegion& confirm_region, uint32_t boot_epoch_ms)
      : monitor_(state_region, confirm_region, real_accessor_, boot_epoch_ms) {}

  // Test/alternate-source constructor: `image_accessor` is consulted
  // instead of the real hardware bridge, so callers (native tests) can
  // prove the genuine positive-confirmation path, not just the fail-
  // closed off-target one.
  OtaBoardTrialBootHealthConfirmer(::ota::platform::FlashRegion& state_region,
                                   ::ota::platform::FlashRegion& confirm_region,
                                   ::ota::storage::IXiaoOtaActiveImageAccessor& image_accessor,
                                   uint32_t boot_epoch_ms)
      : monitor_(state_region, confirm_region, image_accessor, boot_epoch_ms) {}

  // Call exactly once per main-loop tick with the genuine current
  // wall-clock time (caller's own monotonic millis clock) and readiness
  // signals; returns the latched outcome (see
  // ::ota::storage::XiaoOtaTrialHealthOutcome). Callers must react to
  // ANY of the three (Pending -> Confirmed), (Pending -> DeadlineExpired)
  // or (Pending -> ConfirmationUncertain) transitions with exactly one
  // deliberate reboot of their own -- this class never reboots and never
  // touches any hardware watchdog register.
  ::ota::storage::XiaoOtaTrialHealthOutcome tick(uint32_t now_ms, bool radio_ready, bool filesystem_ready,
                                                 bool loop_healthy) {
    return monitor_.tick(now_ms, radio_ready, filesystem_ready, loop_healthy);
  }

  // True while a genuine TRIAL_BOOT state record is in progress --
  // INCLUDING after a same-boot terminal outcome has latched; only a
  // genuine subsequent boot with a fresh (non-trial) state record clears
  // this. Callers use this to suppress deep sleep and competing
  // installs/erases while a trial is live or its outcome is unresolved-
  // -pending-reboot.
  bool isTrialActive() const { return monitor_.isTrialActive(); }

  ::ota::storage::XiaoOtaTrialHealthOutcome outcome() const { return monitor_.outcome(); }
  uint32_t lastConfirmedCounter() const { return monitor_.confirmedCounter(); }

  // Raw eager-read state-record outcome/phase (see
  // XiaoOtaTrialHealthMonitor::stateReadStatus()/statePhase()) -- used
  // by resolveOtaBoardStartupDecision() below to build a typed startup
  // decision that distinguishes "no install history" (Blank), "genuine
  // completed-install evidence" (Found + phase == kPhaseConfirmed), and
  // every other ambiguous/incomplete phase, none of which isTrialActive()
  // alone can tell apart.
  ::ota::storage::XiaoOtaStateReader::ReadStatus stateReadStatus() const { return monitor_.stateReadStatus(); }
  uint32_t statePhase() const { return monitor_.statePhase(); }

private:
  OtaBoardRealActiveImageAccessor real_accessor_;
  ::ota::storage::XiaoOtaTrialHealthMonitor monitor_;
};

// Decorator around a real IOtaStagingSink that refuses to BEGIN a new
// staging session (returns Rejected, touches nothing else) while a
// caller-supplied predicate reports that a trial-boot health window is
// genuinely active or its state is unknown (predicate not yet wired /
// confirmer not yet constructed -- see the backends' fail-closed
// null-pointer handling). A NEW incoming OTA campaign must never be
// allowed to erase/stage over the candidate region while a prior
// install's trial-boot confirmation is still pending: that is a genuine
// production hazard this decorator closes, distinct from (and in
// addition to) OtaBoardInstallCommandProviderV2's existing
// trial-active guard, which only ever gated BUILDING a durable install
// command, never the storage sink's own beginSession()/erase itself.
// Once a session has legitimately begun, all other calls (writeChunk/
// commit/abort/the two optional verified-descriptor/authorized-session
// hooks) delegate unconditionally to the wrapped sink -- this decorator
// only ever gates the initial admission decision, never mid-transfer
// behaviour. Also latches a "storage IO fault observed" flag whenever the
// wrapped sink's writeChunk()/commit() reports IoError -- a real,
// grounded filesystem-failure signal reused by the board wiring as part
// of its genuine (not hardcoded-true) per-tick filesystem-readiness
// check for the trial-boot health monitor.
class OtaBoardTrialGuardedStagingSink : public meshcore::ota::runtime::IOtaStagingSink {
public:
  using TrialActiveOrUnknownPredicate = bool (*)();

  OtaBoardTrialGuardedStagingSink(meshcore::ota::runtime::IOtaStagingSink& wrapped,
                                  TrialActiveOrUnknownPredicate predicate)
      : wrapped_(wrapped), predicate_(predicate) {}

  Result beginSession(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    // Fail closed on an unknown predicate too: a null predicate must
    // never be silently treated as "not active" and permit an erase --
    // exactly like predicate()==true.
    if (predicate_ == nullptr || predicate_()) {
      return Result::Rejected;  // trial-active/unknown: refuse, no erase/state mutation of any kind.
    }
    return wrapped_.beginSession(descriptor);
  }

  Result resumeSession(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    return wrapped_.resumeSession(descriptor);
  }

  Result writeChunk(uint64_t offset, const uint8_t* data, size_t len) override {
    const Result result = wrapped_.writeChunk(offset, data, len);
    if (result == Result::IoError) io_fault_observed_ = true;
    return result;
  }

  Result readChunk(uint64_t offset, uint8_t* out, size_t len) override {
    const Result result = wrapped_.readChunk(offset, out, len);
    if (result == Result::IoError) io_fault_observed_ = true;
    return result;
  }

  Result commit() override {
    const Result result = wrapped_.commit();
    if (result == Result::IoError) io_fault_observed_ = true;
    return result;
  }

  void abort() override { wrapped_.abort(); }

  void onVerifiedWireDescriptor(const uint8_t* wireDescriptor59, size_t wireDescriptorLen,
                                const uint8_t* signature64, size_t signatureLen) override {
    wrapped_.onVerifiedWireDescriptor(wireDescriptor59, wireDescriptorLen, signature64, signatureLen);
  }

  void onAuthorizedSession(const meshcore::ota::runtime::OtaSessionId& session,
                           const uint8_t controller[32]) override {
    wrapped_.onAuthorizedSession(session, controller);
  }

  void onAdmittedOwnerIdentity(const uint8_t owner_public_key[32]) override {
    wrapped_.onAdmittedOwnerIdentity(owner_public_key);
  }

  // Real, grounded (not invented) filesystem-fault signal: true once any
  // writeChunk()/commit() call on the wrapped sink has ever reported
  // IoError this boot. Latched, never auto-clears -- a device that has
  // observed a genuine storage fault must not silently claim
  // filesystem-ready again without a fresh boot.
  bool storageIoFaultObserved() const { return io_fault_observed_; }

private:
  meshcore::ota::runtime::IOtaStagingSink& wrapped_;
  TrialActiveOrUnknownPredicate predicate_;
  bool io_fault_observed_ = false;
};

class OtaBoardCacheOnlyTrustProvider final : public meshcore::ota::runtime::IOtaTrustProvider {
public:
  explicit OtaBoardCacheOnlyTrustProvider(::ota::platform::FlashRegion& candidate) : candidate_(candidate) {}
  bool verifyDescriptorSignature(const uint8_t*, size_t, const uint8_t*, size_t,
                                 uint16_t, uint16_t) override { return false; }
  bool verifyStagedImageHashPolicyOnly(const meshcore::ota::protocol::OtaDescriptor& descriptor) override {
    if (descriptor.exactSizeBytes == 0 || descriptor.exactSizeBytes > candidate_.sizeBytes()) return false;
    ::ota::trust::Sha256 sha;
    uint8_t actual[32];
    return ::ota::trust::ImageHasher::hashRegion(sha, candidate_, descriptor.exactSizeBytes, actual) &&
           !std::memcmp(actual, descriptor.sha256, sizeof(actual));
  }
private:
  ::ota::platform::FlashRegion& candidate_;
};

class OtaBoardCacheOnlyBackend {
  class CacheSink final : public OtaFirmwareStorageSink {
  public:
    using OtaFirmwareStorageSink::OtaFirmwareStorageSink;
    Result commit() override { return Result::Rejected; }
  };
public:
  OtaBoardCacheOnlyBackend(::ota::platform::FlashRegion& candidate, ::ota::platform::FlashRegion& records,
                          OtaBoardTrialGuardedStagingSink::TrialActiveOrUnknownPredicate predicate)
      : trust_(candidate), sink_(candidate), guarded_(sink_, predicate), store_(records) {}

  bool attach(OtaFirmwareIntegration& integration, const ::ota::trust::SignatureVerifier& signatures) {
    integration.attachTrustProvider(&trust_);
    integration.attachLeanSignatureVerifier(&signatures);
    integration.attachStagingSink(&guarded_);
    integration.attachCandidateStore(&store_);
    return integration.backendAvailable();
  }
private:
  OtaBoardCacheOnlyTrustProvider trust_;
  CacheSink sink_;
  OtaBoardTrialGuardedStagingSink guarded_;
  ::ota::storage::OtaCandidateStore store_;
};

}  // namespace ota
}  // namespace mesh
