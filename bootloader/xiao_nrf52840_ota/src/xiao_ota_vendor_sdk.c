#include "xiao_ota_vendor_sdk.h"
#include "xiao_ota_layout.h"
#include "xiao_ota_vendor.h"
#include "pstorage.h"
#include "dfu.h"
#include "nrf_sdm.h"
#include "nrf_error.h"
#include <string.h>

static xiao_ota_vendor_sdk_config_t config;
static pstorage_handle_t settings_handle;
static uint32_t words[6] __attribute__((aligned(4)));
static bool initialized, poisoned, completed;
static uint32_t result;

static void settings_done(pstorage_handle_t *handle, uint8_t op, uint32_t error,
                          uint8_t *data, uint32_t bytes) {
  (void)op;
  (void)data;
  (void)bytes;
  if (handle->module_id != settings_handle.module_id) {
    result = NRF_ERROR_INVALID_STATE;
    poisoned = true;
  } else {
    result = error;
  }
  completed = true;
}

static uint32_t wait_flash(bool callback) {
  uint32_t start = config.ticks();
  while (pstorage_raw_busy() || (callback && !completed)) {
    if (config.feed_existing_dfu_watchdog) config.feed_existing_dfu_watchdog();
    uint32_t error = pstorage_raw_poll();
    if (error != NRF_SUCCESS) {
      poisoned = true;
      return error;
    }
    error = config.poll_soc();
    if (error != NRF_SUCCESS && error != NRF_ERROR_NOT_FOUND) {
      poisoned = true;
      return error;
    }
    if (completed && result != NRF_SUCCESS) {
      poisoned = true;
      return result;
    }
    if (((config.ticks() - start) & UINT32_C(0x00ffffff)) >= config.timeout_ticks) {
      poisoned = true;
      return NRF_ERROR_TIMEOUT;
    }
  }
  return callback ? result : NRF_SUCCESS;
}

uint32_t xiao_ota_vendor_sdk_drain(void) {
  if (!initialized || poisoned) return NRF_ERROR_INVALID_STATE;
  return wait_flash(false);
}

static bool read_internal(void *ctx, uint32_t address, void *out, size_t bytes) {
  (void)ctx;
  if (address >= XIAO_OTA_APP_START && address < XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS &&
      (address >= config.app_end || bytes > config.app_end - address)) return false;
  return config.internal->internal_read(config.internal->ctx, address, out, bytes);
}

static bool sd_enabled(bool *enabled) {
  uint8_t value = 1;
  if (sd_softdevice_is_enabled(&value) != NRF_SUCCESS) {
    poisoned = true;
    return false;
  }
  *enabled = value != 0;
  return true;
}

static bool write_internal(void *ctx, uint32_t address, const void *data, size_t bytes) {
  (void)ctx;
  bool enabled;
  if (poisoned || address < XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS ||
      address > XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + 28 ||
      bytes > XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + 28 - address ||
      bytes > sizeof(words) || ((address | bytes) & 3u) || !sd_enabled(&enabled)) return false;
  if (!enabled) return config.internal->internal_write(config.internal->ctx, address, data, bytes);
  if (xiao_ota_vendor_sdk_drain() != NRF_SUCCESS) return false;
  memcpy(words, data, bytes);
  completed = false;
  result = NRF_SUCCESS;
  uint32_t error = pstorage_store(&settings_handle, (uint8_t *)words, (uint32_t)bytes,
                                 address - XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS);
  if (error != NRF_SUCCESS) {
    poisoned = true;
    return false;
  }
  return wait_flash(true) == NRF_SUCCESS;
}

static bool erase_internal(void *ctx, uint32_t address) {
  (void)ctx;
  bool enabled;
  if (poisoned || address != XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS ||
      !sd_enabled(&enabled)) return false;
  if (!enabled) return config.internal->internal_erase_page(config.internal->ctx, address);
  if (xiao_ota_vendor_sdk_drain() != NRF_SUCCESS) return false;
  completed = false;
  result = NRF_SUCCESS;
  uint32_t error = pstorage_clear(&settings_handle, 4096);
  if (error != NRF_SUCCESS) {
    poisoned = true;
    return false;
  }
  return wait_flash(true) == NRF_SUCCESS;
}

static const xiao_ota_io_t sdk_io = {
  .internal_read = read_internal,
  .internal_write = write_internal,
  .internal_erase_page = erase_internal,
};

uint32_t xiao_ota_vendor_sdk_init(const xiao_ota_vendor_sdk_config_t *input) {
  if (initialized) return NRF_ERROR_INVALID_STATE;
  if (!input || !input->internal || !input->internal->internal_read ||
      !input->internal->internal_write || !input->internal->internal_erase_page ||
      !input->poll_soc || !input->ticks || !input->invalidate_app_grant || !input->timeout_ticks ||
      input->timeout_ticks > UINT32_C(0x007fffff) ||
      input->app_end <= XIAO_OTA_APP_START ||
      input->app_end > XIAO_OTA_APP_START + XIAO_OTA_INSTALL_MAX_SIZE ||
      (input->app_end & 4095u)) return NRF_ERROR_INVALID_PARAM;
  config = *input;
  settings_handle.block_id = XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS;
  pstorage_module_param_t module = {.cb = settings_done};
  uint32_t error = pstorage_register(&module, &settings_handle);
  if (error == NRF_SUCCESS) initialized = true;
  return error;
}

bool xiao_ota_vendor_sdk_upload_begin(void) {
  if (!initialized) return false;
  config.invalidate_app_grant();
  xiao_ota_vendor_recovery_begin();
  return true;
}

bool xiao_ota_vendor_sdk_prepare(uint32_t extent) {
  return xiao_ota_vendor_sdk_upload_begin() && !poisoned &&
         extent <= config.app_end - XIAO_OTA_APP_START &&
         xiao_ota_vendor_sdk_drain() == NRF_SUCCESS &&
         xiao_ota_vendor_prepare(&sdk_io, extent);
}

bool xiao_ota_vendor_sdk_publish(uint32_t extent) {
  return initialized && !poisoned && extent <= config.app_end - XIAO_OTA_APP_START &&
         xiao_ota_vendor_sdk_drain() == NRF_SUCCESS &&
         xiao_ota_vendor_publish(&sdk_io, extent);
}

bool xiao_ota_vendor_sdk_intact(void) {
  return initialized && !poisoned && xiao_ota_app_is_intact(&sdk_io);
}

bool xiao_ota_vendor_sdk_save(const bootloader_settings_t *settings) {
  _Static_assert(sizeof(*settings) == 28, "SDK28 ABI");
  return initialized && !poisoned && xiao_ota_vendor_sdk_drain() == NRF_SUCCESS &&
         xiao_ota_vendor_settings_write(&sdk_io, (const uint8_t *)settings);
}

bool xiao_ota_vendor_sdk_finalize(const bootloader_settings_t *settings) {
  return xiao_ota_vendor_sdk_upload_begin() && !poisoned &&
         xiao_ota_vendor_sdk_drain() == NRF_SUCCESS &&
         xiao_ota_vendor_pending_settings_write(&sdk_io, (const uint8_t *)settings);
}

uint32_t xiao_ota_vendor_pending_check(void) {
  bootloader_settings_t state, after;
  if (!xiao_ota_vendor_sdk_upload_begin()) return NRF_ERROR_INVALID_STATE;
  bool enabled;
  if (!sd_enabled(&enabled)) return NRF_ERROR_INTERNAL;
  if (enabled) return NRF_ERROR_INVALID_STATE;
  if (!initialized || poisoned ||
      !read_internal(NULL, XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS, &state, sizeof(state)))
    return NRF_ERROR_INTERNAL;
  uint8_t tail[128];
  for (uint32_t offset = 28; offset < 4096;) {
    uint32_t bytes = 4096 - offset;
    if (bytes > sizeof(tail)) bytes = sizeof(tail);
    if (!read_internal(NULL, XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS + offset, tail, bytes))
      return NRF_ERROR_INTERNAL;
    for (uint32_t n = 0; n < bytes; n++)
      if (tail[n] != 0xff) return NRF_ERROR_INVALID_STATE;
    offset += bytes;
  }
  if (!read_internal(NULL, XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS, &after, sizeof(after)) ||
      memcmp(&state, &after, sizeof(state))) return NRF_ERROR_INTERNAL;
  bool sd = state.bank_0 == BANK_VALID_SD;
  bool bl = state.bank_1 == BANK_VALID_BOOT;
  if (!sd && !bl) return NRF_ERROR_INVALID_STATE;
  if ((state.sd_image_size | state.bl_image_size | state.app_image_size) & 3u)
    return NRF_ERROR_INVALID_LENGTH;
  if (state.app_image_size || (state.bank_1 != BANK_INVALID_APP && !bl) ||
      (!sd && state.bank_0 != BANK_VALID_APP && state.bank_0 != BANK_INVALID_APP))
    return NRF_ERROR_NOT_SUPPORTED;
  if ((sd && !state.sd_image_size) || (bl && !state.bl_image_size) ||
      (!sd && state.sd_image_size) ||
      state.sd_image_size > XIAO_OTA_APP_START - 0x1000u)
    return NRF_ERROR_NOT_SUPPORTED;
  uint32_t source = state.sd_image_size ? state.sd_image_start : XIAO_OTA_APP_START;
  if (source < XIAO_OTA_APP_START || source >= config.app_end || (source & 4095u))
    return NRF_ERROR_INVALID_ADDR;
  uint32_t remaining = config.app_end - source;
  if (state.sd_image_size > remaining) return NRF_ERROR_DATA_SIZE;
  remaining -= state.sd_image_size;
  if (state.bl_image_size > remaining) return NRF_ERROR_DATA_SIZE;
  remaining -= state.bl_image_size;
  if (state.app_image_size > remaining) return NRF_ERROR_DATA_SIZE;
  if (state.bl_image_size) {
    if (state.bl_image_size > XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS - BOOTLOADER_REGION_START)
      return NRF_ERROR_DATA_SIZE;
    /* A different pending primary cannot replace the approved frozen image. */
    uint32_t error = dfu_bl_image_validate();
    if (error != NRF_SUCCESS) return NRF_ERROR_NOT_SUPPORTED;
  }
  return NRF_SUCCESS;
}
