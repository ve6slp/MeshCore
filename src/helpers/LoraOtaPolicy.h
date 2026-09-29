#pragma once

#include <stdint.h>
#include <array>
#include <cstring>

namespace mesh {

enum class LoraOtaMode : uint8_t {
  Direct = 0,
  RoutedMesh = 1,
  Background = 2,
};

enum class LoraOtaSessionState : uint8_t {
  Idle = 0,
  ManifestPending = 1,
  Ready = 2,
  Downloading = 3,
  Validating = 4,
  Committing = 5,
  Complete = 6,
  Failed = 7,
  Aborted = 8,
};

struct LoraOtaPlan {
  LoraOtaMode mode;
  uint8_t duty_cycle_percent;
  uint32_t airtime_budget_ms;
  uint32_t upload_window_ms;
  uint32_t cadence_ms;
  bool background_allowed;
  bool mesh_path_required;
};

struct LoraOtaManifest {
  uint32_t manifest_version;
  uint32_t firmware_version;
  uint32_t image_size_bytes;
  uint32_t image_crc32;
  uint32_t chunk_size_bytes;
  uint32_t chunk_count;
  uint32_t update_window_ms;
  uint32_t required_bootloader_version;
  uint32_t security_counter;
  uint8_t duty_cycle_percent;
  uint8_t mode;
  uint8_t board_family;
  uint8_t reserved;
  char variant[24];
  char region[16];
};

enum class LoraOtaInstallState : uint8_t {
  Empty = 0,
  CandidateReceiving = 1,
  CandidateReady = 2,
  BackupCopying = 3,
  BackupReady = 4,
  InstallCopying = 5,
  TrialBoot = 6,
  Confirmed = 7,
  RollbackCopying = 8,
  Failed = 9,
};

struct LoraOtaStorageLayout {
  static constexpr uint32_t kQspiTotalBytes = 2u * 1024u * 1024u;
  static constexpr uint32_t kQspiEraseBytes = 4096u;
  static constexpr uint32_t kSensecapAppBytes = 792u * 1024u;
  static constexpr uint32_t kCandidateOffset = 0x000000u;
  static constexpr uint32_t kCandidateSize = kSensecapAppBytes;
  static constexpr uint32_t kBackupOffset = 0x0C6000u;
  static constexpr uint32_t kBackupSize = kSensecapAppBytes;
  static constexpr uint32_t kJournalOffset = 0x18C000u;
  static constexpr uint32_t kJournalSize = 32u * 1024u;
  static constexpr uint32_t kLittleFsOffset = 0x194000u;
  static constexpr uint32_t kLittleFsSize = 432u * 1024u;

  static bool rangesOverlap(uint32_t a_offset, uint32_t a_size, uint32_t b_offset, uint32_t b_size) {
    if (a_size == 0 || b_size == 0) {
      return false;
    }
    const uint32_t a_end = a_offset + a_size;
    const uint32_t b_end = b_offset + b_size;
    return !(a_end <= b_offset || b_end <= a_offset);
  }

  static bool isAligned(uint32_t value, uint32_t alignment) {
    return alignment != 0 && (value % alignment) == 0;
  }

  static bool isValid() {
    if (kQspiTotalBytes != (2u * 1024u * 1024u)) {
      return false;
    }

    if (!isAligned(kCandidateOffset, kQspiEraseBytes) || !isAligned(kCandidateSize, kQspiEraseBytes) ||
        !isAligned(kBackupOffset, kQspiEraseBytes) || !isAligned(kBackupSize, kQspiEraseBytes) ||
        !isAligned(kJournalOffset, kQspiEraseBytes) || !isAligned(kJournalSize, kQspiEraseBytes) ||
        !isAligned(kLittleFsOffset, kQspiEraseBytes) || !isAligned(kLittleFsSize, kQspiEraseBytes)) {
      return false;
    }

    if (kCandidateOffset + kCandidateSize > kQspiTotalBytes ||
        kBackupOffset + kBackupSize > kQspiTotalBytes ||
        kJournalOffset + kJournalSize > kQspiTotalBytes ||
        kLittleFsOffset + kLittleFsSize > kQspiTotalBytes) {
      return false;
    }

    if (rangesOverlap(kCandidateOffset, kCandidateSize, kBackupOffset, kBackupSize) ||
        rangesOverlap(kCandidateOffset, kCandidateSize, kJournalOffset, kJournalSize) ||
        rangesOverlap(kCandidateOffset, kCandidateSize, kLittleFsOffset, kLittleFsSize) ||
        rangesOverlap(kBackupOffset, kBackupSize, kJournalOffset, kJournalSize) ||
        rangesOverlap(kBackupOffset, kBackupSize, kLittleFsOffset, kLittleFsSize) ||
        rangesOverlap(kJournalOffset, kJournalSize, kLittleFsOffset, kLittleFsSize)) {
      return false;
    }

    return true;
  }
};

class LoraOtaPolicy {
public:
  static constexpr uint32_t kMsPerHour = 60UL * 60UL * 1000UL;
  static constexpr uint32_t kMsPerDay = 24UL * kMsPerHour;
  static constexpr uint32_t kMsPer72Hours = 3UL * kMsPerDay;

  static uint8_t clampDutyCycle(uint8_t duty_cycle_percent) {
    if (duty_cycle_percent > 100) {
      return 100;
    }
    return duty_cycle_percent;
  }

  static uint32_t computeAirtimeBudgetMs(uint32_t update_window_ms, uint8_t duty_cycle_percent) {
    uint8_t safe_percent = clampDutyCycle(duty_cycle_percent);
    if (update_window_ms == 0) {
      return 0;
    }

    uint64_t budget = static_cast<uint64_t>(update_window_ms) * safe_percent;
    return static_cast<uint32_t>(budget / 100ULL);
  }

  static uint32_t computeUploadWindowMs(uint32_t update_window_ms, uint8_t duty_cycle_percent) {
    return computeAirtimeBudgetMs(update_window_ms, duty_cycle_percent);
  }

  static uint32_t computeCadenceMs(uint32_t update_window_ms, uint8_t duty_cycle_percent) {
    uint32_t budget = computeAirtimeBudgetMs(update_window_ms, duty_cycle_percent);
    if (budget == 0) {
      return update_window_ms;
    }
    return update_window_ms / (budget > 0 ? (budget / 1000U + 1U) : 1U);
  }

  static bool isBackgroundEligible(uint8_t duty_cycle_percent, float network_load_fraction) {
    if (duty_cycle_percent == 0) {
      return false;
    }

    const float load = network_load_fraction < 0.0f ? 0.0f : network_load_fraction;
    const float safe_load = load > 1.0f ? 1.0f : load;

    return duty_cycle_percent <= 2U && safe_load < 0.8f;
  }

  static bool requiresMeshPath(LoraOtaMode mode) {
    return mode == LoraOtaMode::RoutedMesh || mode == LoraOtaMode::Background;
  }

  static LoraOtaPlan buildPlan(
      LoraOtaMode mode,
      uint32_t update_window_ms,
      uint8_t duty_cycle_percent,
      float network_load_fraction,
      bool direct_radio_available,
      bool mesh_path_available,
      bool multicast_enabled) {
    const uint8_t safe_percent = clampDutyCycle(duty_cycle_percent);
    const uint32_t airtime_budget_ms = computeAirtimeBudgetMs(update_window_ms, safe_percent);
    const uint32_t upload_window_ms = direct_radio_available ? airtime_budget_ms : (airtime_budget_ms / 2U);
    const uint32_t cadence_ms = computeCadenceMs(update_window_ms, safe_percent);
    const bool background_allowed = (mode == LoraOtaMode::Background) && isBackgroundEligible(safe_percent, network_load_fraction);
    const bool mesh_path_required = requiresMeshPath(mode);

    LoraOtaPlan plan = {
      mode,
      safe_percent,
      airtime_budget_ms,
      upload_window_ms,
      cadence_ms,
      background_allowed,
      mesh_path_required && !mesh_path_available,
    };

    if (mode == LoraOtaMode::Direct) {
      plan.background_allowed = false;
      plan.mesh_path_required = false;
      return plan;
    }

    if (mode == LoraOtaMode::RoutedMesh) {
      plan.background_allowed = false;
      plan.mesh_path_required = !mesh_path_available;
      return plan;
    }

    if (mode == LoraOtaMode::Background) {
      plan.background_allowed = multicast_enabled && isBackgroundEligible(safe_percent, network_load_fraction);
      plan.mesh_path_required = !multicast_enabled && !mesh_path_available;
      return plan;
    }

    return plan;
  }
};

class LoraOtaSession {
public:
  static constexpr uint16_t kMaxChunkBitmapBytes = 256;

  LoraOtaSession()
      : state_(LoraOtaSessionState::Idle),
        update_window_ms_(0),
        duty_cycle_percent_(0),
        chunk_count_(0),
        bytes_received_(0),
        bytes_transmitted_(0),
        chunk_size_bytes_(0),
        image_crc32_(0),
        image_size_bytes_(0) {
    chunk_bitmap_.fill(0);
  }

  bool validateManifest(const LoraOtaManifest& manifest) const {
    if (manifest.manifest_version == 0) {
      return false;
    }
    if (manifest.image_size_bytes == 0 || manifest.chunk_size_bytes == 0) {
      return false;
    }
    if (manifest.chunk_count == 0 || manifest.chunk_count > (kMaxChunkBitmapBytes * 8U)) {
      return false;
    }
    if (manifest.duty_cycle_percent == 0 || manifest.duty_cycle_percent > 100) {
      return false;
    }
    if (manifest.required_bootloader_version == 0) {
      return false;
    }
    if (manifest.security_counter == 0) {
      return false;
    }
    if (!LoraOtaStorageLayout::isValid()) {
      return false;
    }

    const LoraOtaMode mode = static_cast<LoraOtaMode>(manifest.mode);
    if (mode != LoraOtaMode::Direct && mode != LoraOtaMode::RoutedMesh && mode != LoraOtaMode::Background) {
      return false;
    }

    return true;
  }

  bool begin(const LoraOtaManifest& manifest) {
    if (!validateManifest(manifest)) {
      state_ = LoraOtaSessionState::Failed;
      return false;
    }

    manifest_ = manifest;
    state_ = LoraOtaSessionState::ManifestPending;
    chunk_count_ = manifest.chunk_count;
    chunk_size_bytes_ = manifest.chunk_size_bytes;
    image_size_bytes_ = manifest.image_size_bytes;
    image_crc32_ = manifest.image_crc32;
    update_window_ms_ = manifest.update_window_ms;
    duty_cycle_percent_ = manifest.duty_cycle_percent;
    chunk_bitmap_.fill(0);
    bytes_received_ = 0;
    bytes_transmitted_ = 0;
    airtime_used_ms_ = 0;
    install_state_ = LoraOtaInstallState::CandidateReceiving;
    return true;
  }

  bool acceptManifest(const LoraOtaManifest& manifest) {
    if (!validateManifest(manifest)) {
      state_ = LoraOtaSessionState::Failed;
      return false;
    }

    manifest_ = manifest;
    chunk_count_ = manifest.chunk_count;
    chunk_size_bytes_ = manifest.chunk_size_bytes;
    image_size_bytes_ = manifest.image_size_bytes;
    image_crc32_ = manifest.image_crc32;
    update_window_ms_ = manifest.update_window_ms;
    duty_cycle_percent_ = manifest.duty_cycle_percent;
    chunk_bitmap_.fill(0);
    state_ = LoraOtaSessionState::Ready;
    install_state_ = LoraOtaInstallState::CandidateReceiving;
    return true;
  }

  bool recordChunk(uint32_t chunk_index, uint32_t chunk_crc32) {
    if (state_ == LoraOtaSessionState::Idle || state_ == LoraOtaSessionState::Failed || state_ == LoraOtaSessionState::Aborted) {
      return false;
    }
    if (chunk_index >= chunk_count_ || chunk_count_ == 0) {
      return false;
    }

    const uint32_t byte_index = chunk_index / 8U;
    const uint8_t bit_mask = static_cast<uint8_t>(1U << (chunk_index % 8U));
    if (byte_index >= chunk_bitmap_.size()) {
      return false;
    }

    if ((chunk_bitmap_[byte_index] & bit_mask) != 0U) {
      return true;
    }

    chunk_bitmap_[byte_index] |= bit_mask;
    bytes_received_ += chunk_size_bytes_;
    (void)chunk_crc32;

    if (isComplete()) {
      state_ = LoraOtaSessionState::Validating;
    } else {
      state_ = LoraOtaSessionState::Downloading;
    }
    return true;
  }

  bool setComplete() {
    if (state_ == LoraOtaSessionState::Failed || state_ == LoraOtaSessionState::Aborted) {
      return false;
    }
    if (!isComplete()) {
      return false;
    }
    state_ = LoraOtaSessionState::Complete;
    install_state_ = LoraOtaInstallState::Confirmed;
    return true;
  }

  bool markFailed() {
    state_ = LoraOtaSessionState::Failed;
    return true;
  }

  bool abort() {
    state_ = LoraOtaSessionState::Aborted;
    return true;
  }

  uint32_t countReceivedChunks() const {
    uint32_t count = 0;
    for (uint32_t i = 0; i < chunk_count_; ++i) {
      const uint32_t byte_index = i / 8U;
      const uint8_t bit_mask = static_cast<uint8_t>(1U << (i % 8U));
      if (byte_index < chunk_bitmap_.size() && (chunk_bitmap_[byte_index] & bit_mask) != 0U) {
        ++count;
      }
    }
    return count;
  }

  uint32_t countMissingChunks() const {
    return chunk_count_ > countReceivedChunks() ? (chunk_count_ - countReceivedChunks()) : 0U;
  }

  bool isComplete() const {
    return countReceivedChunks() == chunk_count_;
  }

  bool canTransmitAdditional(uint32_t airtime_used_ms) const {
    const uint32_t budget_ms = LoraOtaPolicy::computeAirtimeBudgetMs(update_window_ms_, duty_cycle_percent_);
    return airtime_used_ms < budget_ms;
  }

  void noteAirTimeUsage(uint32_t airtime_used_ms) {
    if (airtime_used_ms > airtime_used_ms_) {
      airtime_used_ms_ = airtime_used_ms;
    }
    if (state_ == LoraOtaSessionState::Downloading || state_ == LoraOtaSessionState::Validating) {
      install_state_ = LoraOtaInstallState::CandidateReceiving;
    }
  }

  uint32_t budgetMs() const {
    return LoraOtaPolicy::computeAirtimeBudgetMs(update_window_ms_, duty_cycle_percent_);
  }

  uint32_t remainingBudgetMs(uint32_t airtime_used_ms) const {
    const uint32_t budget = budgetMs();
    return budget > airtime_used_ms ? (budget - airtime_used_ms) : 0U;
  }

  uint32_t getChunkCount() const { return chunk_count_; }
  uint32_t getImageSizeBytes() const { return image_size_bytes_; }
  uint32_t getBytesReceived() const { return bytes_received_; }
  uint32_t getBytesTransmitted() const { return bytes_transmitted_; }
  void setBytesTransmitted(uint32_t transmitted) { bytes_transmitted_ = transmitted; }
  uint32_t getUpdateWindowMs() const { return update_window_ms_; }
  uint32_t getDutyCyclePercent() const { return duty_cycle_percent_; }
  LoraOtaSessionState getState() const { return state_; }
  LoraOtaInstallState getInstallState() const { return install_state_; }
  uint32_t getAirTimeUsedMs() const { return airtime_used_ms_; }

private:
  LoraOtaManifest manifest_;
  LoraOtaSessionState state_;
  LoraOtaInstallState install_state_;
  uint32_t update_window_ms_;
  uint32_t duty_cycle_percent_;
  uint32_t chunk_count_;
  uint32_t bytes_received_;
  uint32_t bytes_transmitted_;
  uint32_t chunk_size_bytes_;
  uint32_t image_crc32_;
  uint32_t image_size_bytes_;
  uint32_t airtime_used_ms_;
  std::array<uint8_t, kMaxChunkBitmapBytes> chunk_bitmap_;
};

}  // namespace mesh
