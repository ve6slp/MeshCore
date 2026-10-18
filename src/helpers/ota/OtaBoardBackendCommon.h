#pragma once

#include <atomic>
#include <cstdio>
#include <cstring>
#include <helpers/ota/OtaFirmwareBackend.h>
#include <ota/platform/Nrf52FlashLayoutContract.h>
#include <ota/storage/XiaoOtaActiveExtentBridge.h>
#include <ota/storage/XiaoOtaBootInfoReader.h>
#include <ota/storage/XiaoOtaCommandRecord.h>
#include <ota/storage/XiaoOtaTrialBootConfirmation.h>
#include <ota/storage/XiaoOtaTrialHealthMonitor.h>

namespace mesh { namespace ota {

template<class PhysicalRadio, class Wrapper>
bool applyCheckedOtaRadioProfile(PhysicalRadio& radio, Wrapper& wrapper,
                                 float frequency, float bandwidth, uint8_t sf, uint8_t cr) {
  if (radio.standby() != 0 || radio.setFrequency(frequency) != 0 ||
      radio.setSpreadingFactor(sf) != 0 || radio.setBandwidth(bandwidth) != 0 ||
      radio.setCodingRate(cr) != 0) return false;
  wrapper.begin();
  if (radio.setPreambleLength(Wrapper::preambleLengthForSF(sf)) != 0) return false;
  const auto timing = wrapper.calcMaxPacketMillis(sf, bandwidth, cr, Wrapper::preambleLengthForSF(sf));
  radio.setPreambleMillis(timing.preambleMillis);
  radio.setMaxPayloadMillis(timing.payloadMillis);
  uint8_t unused = 0;
  wrapper.recvRaw(&unused, 0);
  return wrapper.isInRecvMode() && wrapper.probeDriverStatus();
}

using OtaBoardTrialHealthOutcome = ::ota::storage::XiaoOtaTrialHealthOutcome;

class OtaBoardRealActiveImageAccessor : public ::ota::storage::IXiaoOtaActiveImageAccessor {
public:
  ::ota::storage::XiaoOtaExtentResolutionStep stepExtentResolution(
      uint32_t maxBytes, const uint8_t** image, uint32_t* extent) override {
    return resolver_.step(maxBytes, image, extent);
  }
private:
  ::ota::storage::XiaoOtaIncrementalExtentResolver resolver_;
};

class OtaBoardTrialBootHealthConfirmer {
public:
  OtaBoardTrialBootHealthConfirmer(::ota::platform::FlashRegion& state,
      ::ota::platform::FlashRegion& confirm, uint32_t bootEpochMs)
      : monitor_(state, confirm, image_, bootEpochMs) {}
  OtaBoardTrialBootHealthConfirmer(::ota::platform::FlashRegion& state,
      ::ota::platform::FlashRegion& confirm, ::ota::storage::IXiaoOtaActiveImageAccessor& image,
      uint32_t bootEpochMs) : monitor_(state, confirm, image, bootEpochMs) {}
  OtaBoardTrialHealthOutcome tick(uint32_t now, bool radio, bool filesystem, bool loop) {
    return monitor_.tick(now, radio, filesystem, loop);
  }
  bool isTrialActive() const { return monitor_.isTrialActive(); }
  ::ota::storage::XiaoOtaStateReader::ReadStatus stateReadStatus() const {
    return monitor_.stateReadStatus();
  }
  uint32_t statePhase() const { return monitor_.statePhase(); }
private:
  OtaBoardRealActiveImageAccessor image_;
  ::ota::storage::XiaoOtaTrialHealthMonitor monitor_;
};

namespace v4 {

struct NrfRunningContext {
  uint8_t settings[28] = {};
  const uint8_t* image = nullptr;
  uint32_t capacity = 0;
  bool settingsTailErased = false;
};

class NrfRunningReader {
public:
  virtual ~NrfRunningReader() = default;
  virtual bool read(NrfRunningContext& out) const {
    out = NrfRunningContext();
#if defined(NRF52840_XXAA)
    const auto* settings = reinterpret_cast<const uint8_t*>(0xFF000u);
    std::memcpy(out.settings, settings, sizeof(out.settings));
    out.image = reinterpret_cast<const uint8_t*>(OTA_NRF52_INTERNAL_IMAGE_OFFSET);
    out.capacity = OTA_NRF52_INTERNAL_IMAGE_SIZE;
    out.settingsTailErased = true;
    for (uint32_t i = sizeof(out.settings); i < 4096; ++i)
      if (settings[i] != 0xFF) out.settingsTailErased = false;
    return true;
#else
    return false;
#endif
  }
};

// Reads only boot-owned records and live APP/SDK bytes. No floor initialization,
// SDK repair, formatting, key generation, or personality migration occurs here.
class NrfBootSafety {
public:
  using State = ::ota::storage::XiaoOtaStateReader;
  using Floor = ::ota::storage::XiaoOtaFloorReader;
  using Command = ::ota::storage::XiaoOtaCommandRecordV3;
  using Bridge = ::ota::storage::XiaoOtaActiveExtentBridge;
  struct Snapshot {
    NrfRunningContext running;
    uint32_t rawBytes = 0, backupBytes = 0, floor = 0;
    uint32_t phase = 0, counter = 0;
    uint64_t transaction = 0;
    uint8_t rawHash[32] = {}, backupHash[32] = {}, candidateHash[32] = {};
    bool confirmed = false;
  };
  NrfBootSafety(::ota::platform::FlashRegion& commands, ::ota::platform::FlashRegion& state,
      ::ota::platform::FlashRegion& floor, ::ota::platform::FlashRegion& confirm,
      const NrfRunningReader& running, const ::ota::trust::SignatureVerifier& signatures,
      const Policy& policy)
      : commands_(commands), state_(state), floor_(floor), confirm_(confirm),
        running_(running), signatures_(signatures), policy_(policy) {}

  bool qualified() const {
    ::ota::storage::XiaoOtaBootInfoReader::Info info;
    using Reader = ::ota::storage::XiaoOtaBootInfoReader;
    return Reader::classifyCurrent(info) == Reader::RecordStatus::Found &&
        info.boardTargetId == ((uint32_t(policy_.boardFamily) << 16) | policy_.boardVariant) &&
        info.roleId == policy_.role && info.algorithmId == policy_.algorithmId &&
        info.keyId == policy_.keyId &&
        (info.capabilityFlags & policy_.bootloaderCapabilities) == policy_.bootloaderCapabilities;
  }

  bool stockNormal() const {
    ::ota::storage::XiaoOtaBootInfoReader::Info info;
    using Reader = ::ota::storage::XiaoOtaBootInfoReader;
    if (Reader::classifyCurrent(info) != Reader::RecordStatus::Blank) return false;
    Snapshot snapshot;
    if (!readRunning(snapshot) || !blank(commands_) || !blank(state_) ||
        !blank(floor_) || !blank(confirm_)) return false;
    NrfRunningContext after;
    return running_.read(after) && sameRunning(snapshot.running, after);
  }

  bool normal(Snapshot& out) const {
    out = Snapshot();
    if (!readRunning(out)) return false;
    uint8_t state[State::kRecordBytes] = {};
    const auto status = State::readNewestWithStatus(state_, state);
    if (status != State::ReadStatus::Blank && status != State::ReadStatus::Found) return false;
    uint8_t floorHash[32]; uint32_t floorExtent = 0;
    if (!strictFloor(out.floor, floorExtent, floorHash)) return false;
    if (status == State::ReadStatus::Blank) {
      if (out.floor || !blank(confirm_)) return false;
      if (floorExtent && (floorExtent != out.rawBytes ||
          std::memcmp(floorHash, out.rawHash, 32))) return false;
      if (!floorExtent && !all(floorHash, 32, 0)) return false;
    } else {
      out.phase = State::phase(state);
      out.counter = State::candidateCounter(state);
      out.transaction = State::transactionNonce(state);
      std::memcpy(out.candidateHash, State::candidateHashSha256(state), 32);
      if (!out.transaction) return false;
      if (out.phase == State::kPhaseConfirmed) {
        const auto bank = Bridge::decodeBank0FromRaw28Bytes(out.running.settings);
        if (out.floor != out.counter || floorExtent != out.rawBytes ||
            bank.bank_0_crc != Bridge::crc16Compute(out.running.image, out.rawBytes) ||
            std::memcmp(out.rawHash, floorHash, 32) ||
            std::memcmp(out.rawHash, out.candidateHash, 32) ||
            std::memcmp(out.rawHash, State::installedHashSha256(state), 32)) return false;
        out.confirmed = true;
      } else if (out.phase == State::kPhaseFailedMax) {
        if (out.counter <= out.floor || State::activeImageExtent(state) != out.backupBytes ||
            std::memcmp(state + 76, out.backupHash, 32) || !savedSettingsMatch(state, out.running))
          return false;
        if (floorExtent && ((floorExtent != out.rawBytes && floorExtent != out.backupBytes) ||
            std::memcmp(floorHash, floorExtent == out.rawBytes ? out.rawHash : out.backupHash, 32)))
          return false;
      } else return false;
    }
    if (!commandsSafe(out)) return false;
    uint8_t afterState[State::kRecordBytes] = {}, afterHash[32]; uint32_t afterFloor, afterExtent;
    NrfRunningContext after;
    return State::readNewestWithStatus(state_, afterState) == status &&
        !std::memcmp(state, afterState, sizeof(state)) &&
        strictFloor(afterFloor, afterExtent, afterHash) && afterFloor == out.floor &&
        afterExtent == floorExtent && !std::memcmp(afterHash, floorHash, 32) &&
        running_.read(after) && sameRunning(out.running, after);
  }

  bool readRunning(Snapshot& out) const {
    if (!running_.read(out.running)) return false;
    const auto bank = Bridge::decodeBank0FromRaw28Bytes(out.running.settings);
    const uint16_t bank1 = out.running.settings[4] | uint16_t(out.running.settings[5]) << 8;
    if (!out.running.settingsTailErased || !out.running.image ||
        bank.bank_0 != ::ota::storage::kBankValidApp || (bank1 != 0xFE && bank1 != 0xFF) ||
        bank.bank_0_size < 8 || bank.bank_0_size > out.running.capacity ||
        bank.bank_0_size > OTA_NRF52_INTERNAL_IMAGE_SIZE || all(out.running.image, 8, 0xFF))
      return false;
    if (bank.bank_0_crc && Bridge::crc16Compute(out.running.image, bank.bank_0_size) != bank.bank_0_crc)
      return false;
    out.rawBytes = bank.bank_0_size;
    out.backupBytes = (out.rawBytes + 3) & ~uint32_t(3);
    if (out.backupBytes > out.running.capacity) return false;
    Bridge::computeFreshHash(out.running.image, out.rawBytes, out.rawHash);
    Bridge::computeFreshHash(out.running.image, out.backupBytes, out.backupHash);
    return true;
  }

  bool strictFloor(uint32_t& counter, uint32_t& extent, uint8_t hash[32]) const {
    uint8_t best[Floor::kRecordBytes] = {};
    uint32_t sequence = 0; bool found = false;
    if (!pairGeometry(floor_)) return false;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      uint8_t record[Floor::kRecordBytes];
      const uint32_t offset = slot * floor_.eraseUnitBytes();
      if (!read(floor_, offset, record, sizeof(record))) return false;
      if (!Floor::isValidRecord(record, sizeof(record))) {
        if (!blankRange(floor_, offset, floor_.eraseUnitBytes())) return false;
        continue;
      }
      if (!blankRange(floor_, offset + sizeof(record), floor_.eraseUnitBytes() - sizeof(record)))
        return false;
      const uint32_t next = le32(record + 8);
      if (found && sequence == next) return false;
      if (!found || next > sequence) { found = true; sequence = next; std::memcpy(best, record, sizeof(best)); }
    }
    if (!found) return false;
    counter = le32(best + 12); extent = le32(best + 16); std::memcpy(hash, best + 20, 32);
    return true;
  }

  static bool blank(const ::ota::platform::FlashRegion& region) {
    return region.isValid() && blankRange(region, 0, region.sizeBytes());
  }
  static uint32_t le32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
  }
private:
  static bool all(const uint8_t* p, size_t n, uint8_t value) {
    for (size_t i = 0; i < n; ++i) if (p[i] != value) return false;
    return true;
  }
  static bool read(const ::ota::platform::FlashRegion& region, uint32_t offset, uint8_t* p, size_t n) {
    return ::ota::platform::isOk(region.read(offset, p, n));
  }
  static bool blankRange(const ::ota::platform::FlashRegion& region, uint32_t offset, uint32_t n) {
    uint8_t bytes[256];
    for (uint32_t done = 0; done < n;) {
      const uint32_t count = n - done < sizeof(bytes) ? n - done : sizeof(bytes);
      if (!read(region, offset + done, bytes, count) || !all(bytes, count, 0xFF)) return false;
      done += count;
    }
    return true;
  }
  static bool sameRunning(const NrfRunningContext& a, const NrfRunningContext& b) {
    return a.image == b.image && a.capacity == b.capacity &&
        a.settingsTailErased == b.settingsTailErased && !std::memcmp(a.settings, b.settings, 28);
  }
  static bool pairGeometry(const ::ota::platform::FlashRegion& region) {
    return region.isValid() && region.eraseUnitBytes() == 4096 && region.sizeBytes() == 8192;
  }
  bool savedSettingsMatch(const uint8_t state[State::kRecordBytes], const NrfRunningContext& running) const {
    for (uint32_t slot = 0; slot < 2; ++slot) {
      uint8_t record[State::kRecordBytes], sidecar[88];
      const uint32_t offset = slot * state_.eraseUnitBytes();
      if (!read(state_, offset, record, sizeof(record))) return false;
      if (std::memcmp(record, state, sizeof(record))) continue;
      if (!read(state_, offset + 0x100, sidecar, sizeof(sidecar))) return false;
      return le32(sidecar) == 0x58534944 && sidecar[4] == 1 && !sidecar[5] &&
          sidecar[6] == sizeof(sidecar) && !sidecar[7] &&
          le32(sidecar + 80) == ::ota::storage::Crc32::computeFinalized(sidecar, 80) &&
          le32(sidecar + 84) == State::kCommitMarker && !std::memcmp(sidecar + 8, state + 8, 12) &&
          !std::memcmp(sidecar + 52, running.settings, 28);
    }
    return false;
  }
  bool commandsSafe(const Snapshot& snapshot) const {
    if (!pairGeometry(commands_)) return false;
    uint8_t records[2][Command::kRecordBytes]; bool valid[2] = {};
    meshcore::ota::protocol::OtaDescriptor descriptors[2];
    int newest = -1;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      const uint32_t offset = slot * commands_.eraseUnitBytes();
      if (!read(commands_, offset, records[slot], sizeof(records[slot]))) return false;
      valid[slot] = Command::isValidRecord(records[slot], sizeof(records[slot]));
      if (!valid[slot]) {
        if (!blankRange(commands_, offset, commands_.eraseUnitBytes())) return false;
        continue;
      }
      if (!blankRange(commands_, offset + sizeof(records[slot]),
                       commands_.eraseUnitBytes() - sizeof(records[slot]))) return false;
      using namespace meshcore::ota::protocol;
      auto& d = descriptors[slot];
      if (decodeOtaDescriptorCanonical(Command::wireDescriptorOf(records[slot]), 59, d) !=
          OtaDescriptorCodecResult::Ok || d.boardFamily != policy_.boardFamily ||
          d.boardVariant != policy_.boardVariant || d.role != policy_.role ||
          d.appAddress != policy_.appAddress || d.formatId != policy_.formatId ||
          d.keyId != policy_.keyId || d.algorithmId != policy_.algorithmId ||
          !d.exactSizeBytes || d.exactSizeBytes > policy_.maxImageBytes ||
          (d.minBootloaderCapabilities & ~policy_.bootloaderCapabilities) ||
          !signatures_.verify(Command::signatureOf(records[slot]), 64,
              Command::wireDescriptorOf(records[slot]), 59, Command::admittedSignerKeyOf(records[slot]), 32))
        return false;
      if (newest >= 0 && Command::sequenceOf(records[slot]) == Command::sequenceOf(records[newest]))
        return false;
      if (newest < 0 || Command::sequenceOf(records[slot]) > Command::sequenceOf(records[newest]))
        newest = slot;
    }
    for (uint32_t slot = 0; slot < 2; ++slot) {
      if (!valid[slot] || descriptors[slot].securityCounter <= snapshot.floor) continue;
      if (newest < 0 || snapshot.phase != State::kPhaseFailedMax ||
          snapshot.transaction != Command::transactionNonceOf(records[newest]) ||
          snapshot.counter != descriptors[newest].securityCounter ||
          std::memcmp(snapshot.candidateHash, descriptors[newest].sha256, 32)) return false;
    }
    return true;
  }
  ::ota::platform::FlashRegion& commands_;
  ::ota::platform::FlashRegion& state_;
  ::ota::platform::FlashRegion& floor_;
  ::ota::platform::FlashRegion& confirm_;
  const NrfRunningReader& running_;
  const ::ota::trust::SignatureVerifier& signatures_;
  const Policy& policy_;
};

class NrfFirmwarePlatform final : public FirmwarePlatform {
public:
  using Entropy = bool (*)(uint8_t*, size_t);
  NrfFirmwarePlatform(const Policy& policy, ::ota::platform::FlashRegion& payload,
      ::ota::platform::FlashRegion& metadata, ::ota::platform::FlashRegion& commands,
      ::ota::platform::FlashRegion& state, ::ota::platform::FlashRegion& floor,
      ::ota::platform::FlashRegion& confirm, const ::ota::trust::SignatureVerifier& signatures,
      const NrfRunningReader& running, Entropy entropy)
      : FirmwarePlatform(policy, payload, metadata, signatures), commands_(commands), state_(state),
        safety_(commands, state, floor, confirm, running, signatures, policy_),
        trial_(state, confirm, 0), entropy_(entropy) {}
  bool normalProven() {
    if (!safety_.qualified()) return safety_.stockNormal();
    NrfBootSafety::Snapshot snapshot;
    return !trial_.isTrialActive() && safety_.normal(snapshot);
  }
  bool installationReady() {
    NrfBootSafety::Snapshot snapshot;
    stagingAllowed_ = safety_.qualified() && !trial_.isTrialActive() && safety_.normal(snapshot);
    return stagingAllowed_;
  }
  Result random(uint8_t* out, size_t size) override {
    return out && size && entropy_ && entropy_(out, size) ? Result::Ok : Result::Io;
  }
  Result evidence(RunningEvidence& out) override {
    out = RunningEvidence();
    NrfBootSafety::Snapshot snapshot;
    if (!safety_.qualified()) return Result::Unsupported;
    if (trial_.isTrialActive()) {
      if (safety_.readRunning(snapshot)) { std::memcpy(out.hash, snapshot.rawHash, 32); out.flags = 2; }
      uint32_t extent; uint8_t hash[32];
      if (safety_.strictFloor(out.floor, extent, hash)) out.flags |= 1;
      return Result::Ok;
    }
    if (!safety_.normal(snapshot)) return Result::State;
    out.floor = snapshot.floor;
    std::memcpy(out.hash, snapshot.rawHash, 32);
    out.flags = 3 | (snapshot.confirmed ? 4 : 0);
    return Result::Ok;
  }
  Result validateInstall(const uint8_t canonical[59], const uint8_t signature[64],
                          const uint8_t signer[32]) override {
    if (mutationAllowed() != Result::Ok) return Result::Busy;
    return verifyRawImage(canonical, signature, signer);
  }
  Result activate(const uint8_t canonical[59], const uint8_t signature[64],
                  const uint8_t signer[32], const uint8_t transaction[16], uint32_t generation) override {
    if (!canonical || !signature || !signer || !transaction || !generation) return Result::Invalid;
    const uint64_t nonce = transactionNonce(transaction, generation, canonical, signer);
    if (!nonce) return Result::Invalid;
    using Command = ::ota::storage::XiaoOtaCommandRecordV3;
    uint8_t existing[Command::kRecordBytes];
    if (Command::readNewest(commands_, existing) &&
        Command::transactionNonceOf(existing) == nonce) {
      const bool same = !std::memcmp(Command::wireDescriptorOf(existing), canonical, 59) &&
          !std::memcmp(Command::signatureOf(existing), signature, 64) &&
          !std::memcmp(Command::admittedSignerKeyOf(existing), signer, 32);
      if (same) installPending_ = true;
      return same ? Result::Ok : Result::Integrity;
    }
    const Result checked = validateInstall(canonical, signature, signer);
    if (checked != Result::Ok) return checked;
    NrfBootSafety::Snapshot original;
    if (!safety_.normal(original)) return Result::Busy;
    ::ota::storage::XiaoOtaCommandV3Fields fields;
    fields.transaction_nonce = nonce;
    std::memcpy(fields.wire_descriptor, canonical, 59);
    std::memcpy(fields.signature_ed25519, signature, 64);
    std::memcpy(fields.admitted_signer_public_key_ed25519, signer, 32);
    fields.active_image_extent = original.backupBytes;
    std::memcpy(fields.active_image_hash_sha256, original.backupHash, 32);
    installPending_ = true;
    return Command::writeNext(commands_, fields) ? Result::Ok : Result::Io;
  }
  Result lifecycle(Phase& phase) override {
    if (!haveCandidate_) return Result::State;
    uint8_t state[NrfBootSafety::State::kRecordBytes];
    if (NrfBootSafety::State::readNewestWithStatus(state_, state) !=
        NrfBootSafety::State::ReadStatus::Found ||
        NrfBootSafety::State::transactionNonce(state) !=
            transactionNonce(latest_.transaction, latest_.generation, canonical_, signer_) ||
        NrfBootSafety::State::candidateCounter(state) != read32(canonical_ + 45) ||
        std::memcmp(NrfBootSafety::State::candidateHashSha256(state), canonical_ + 13, 32))
      return Result::State;
    if (trial_.isTrialActive()) {
      if (trial_.stateReadStatus() != NrfBootSafety::State::ReadStatus::Found ||
          trial_.statePhase() != NrfBootSafety::State::kPhaseTrialBoot) return Result::State;
      phase = Phase::Trial;
      return Result::Ok;
    }
    NrfBootSafety::Snapshot snapshot;
    if (!safety_.qualified() || !safety_.normal(snapshot)) return Result::State;
    if (snapshot.confirmed) { phase = Phase::Confirmed; return Result::Ok; }
    if (snapshot.phase == NrfBootSafety::State::kPhaseFailedMax) { phase = Phase::Failed; return Result::Ok; }
    return Result::State;
  }
  OtaBoardTrialHealthOutcome health(uint32_t now, bool radio, bool filesystem, bool loop) {
    return trial_.tick(now, radio, filesystem && !storageFaultObserved(), loop);
  }
  bool trialActive() const { return trial_.isTrialActive(); }
  bool activationPending() const { return installPending_; }
  static uint64_t transactionNonce(const uint8_t transaction[16], uint32_t generation,
      const uint8_t canonical[59], const uint8_t signer[32]) {
    static constexpr char domain[] = "MeshCore OTA boot transaction v4";
    ::ota::trust::Sha256 hash;
    hash.update(reinterpret_cast<const uint8_t*>(domain), sizeof(domain));
    hash.update(transaction, 16);
    uint8_t gen[4], digest[32]; write32(gen, generation);
    hash.update(gen, sizeof(gen)); hash.update(canonical, 59); hash.update(signer, 32); hash.finish(digest);
    uint64_t nonce = 0;
    for (size_t i = 0; i < 8; ++i) nonce = (nonce << 8) | digest[i];
    return nonce;
  }
protected:
  Result mutationAllowed() override {
    return stagingAllowed_ && !installPending_ && !trial_.isTrialActive() ? Result::Ok : Result::Busy;
  }
private:
  ::ota::platform::FlashRegion& commands_;
  ::ota::platform::FlashRegion& state_;
  NrfBootSafety safety_;
  OtaBoardTrialBootHealthConfirmer trial_;
  Entropy entropy_;
  bool installPending_ = false;
  bool stagingAllowed_ = false;
};

}}}
