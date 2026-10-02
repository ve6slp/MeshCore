#include <Arduino.h>   // needed for PlatformIO
#include <Mesh.h>
#include "MyMesh.h"
// Pure templates, no Arduino/OTA-feature dependency: the trial-safe mount
// call sites below apply unconditionally (even when MESHCORE_LORA_OTA is
// compiled out, ota_allow_destructive_boot_writes is simply always true).
#include "helpers/ota/OtaTrialSafeFilesystemMount.h"

#if MESHCORE_LORA_OTA
// Genuine earliest-boot-phase preflight (see the weak default's doc
// comment in MyMesh.cpp and the real implementations in
// variants/*/Ota*Backend.cpp): declared here (not exposed via MyMesh.h)
// because it must be queried strictly BEFORE store.begin()/the_mesh.begin()
// -- i.e. before either object exists in a usable state -- to gate their
// own identity/prefs/migration writes below.
bool otaBoardEarlyBootTrialOrUnknown();
#endif


// Believe it or not, this std C function is busted on some platforms!
static uint32_t _atoi(const char* sp) {
  uint32_t n = 0;
  while (*sp && *sp >= '0' && *sp <= '9') {
    n *= 10;
    n += (*sp++ - '0');
  }
  return n;
}

// interface manager
#include <helpers/MultiSerialInterface.h>
MultiSerialInterface interface_manager;

// include bluetooth interface
#if defined(BLE_PIN_CODE)
  #ifdef ESP32
    // include esp32 bluetooth interface
    #include <helpers/esp32/SerialBLEInterface.h>
    SerialBLEInterface bluetooth_interface;
  #elif defined(NRF52_PLATFORM)
    // include nrf52 bluetooth interface
    #include <helpers/nrf52/SerialBLEInterface.h>
    SerialBLEInterface bluetooth_interface;
  #else
    #error "SerialBLEInterface is not defined for this platform"
  #endif
#endif

// include wifi interface
#ifdef WIFI_SSID
  #ifndef TCP_PORT
    #define TCP_PORT 5000
  #endif
  #ifdef ESP32
    // include esp32 wifi interface
    #include <helpers/esp32/SerialWifiInterface.h>
    SerialWifiInterface wifi_interface;
  #else
    #error "SerialWifiInterface is not defined for this platform"
  #endif
#endif

// include usb interface
#if defined(ENABLE_USB_INTERFACE)
  #include <helpers/ArduinoSerialInterface.h>
  ArduinoSerialInterface usb_serial_interface;
#endif

// include ethernet interface
#if defined(ETHERNET_ENABLED)
  #include <helpers/ethernet/EthernetInterface.h>
  ETHERNET_CLASS ethernet_interface;
#endif

// include hardware serial interface
#if defined(SERIAL_RX)
  #include <helpers/ArduinoSerialInterface.h>
  ArduinoSerialInterface hardware_serial_interface;
  HardwareSerial companion_serial(1);
#endif

// platform file system
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  #include <InternalFileSystem.h>
  #if defined(QSPIFLASH)
    #include <CustomLFS_QSPIFlash.h>
    DataStore store(InternalFS, QSPIFlash, rtc_clock);
  #else
    #if defined(EXTRAFS)
      #include <CustomLFS.h>
      CustomLFS ExtraFS(0xD4000, 0x19000, 128);
      DataStore store(InternalFS, ExtraFS, rtc_clock);
    #else
      DataStore store(InternalFS, rtc_clock);
    #endif
  #endif
#elif defined(RP2040_PLATFORM)
  #include <LittleFS.h>
  DataStore store(LittleFS, rtc_clock);
#elif defined(ESP32)
  #include <SPIFFS.h>
  DataStore store(SPIFFS, rtc_clock);
#endif

/* GLOBAL OBJECTS */
#ifdef DISPLAY_CLASS
  #include "UITask.h"
  UITask ui_task(&board, &interface_manager);
#endif

StdRNG fast_rng;
SimpleMeshTables tables;
MyMesh the_mesh(radio_driver, fast_rng, rtc_clock, tables, store
   #ifdef DISPLAY_CLASS
      , &ui_task
   #endif
);

/* END GLOBAL OBJECTS */

void halt() {
  while (1) ;
}

/* WIFI RECONNECT TRACKERS */
#if defined(ESP32) && defined(WIFI_SSID)
  bool wifi_needs_reconnect = false;
  unsigned long last_wifi_reconnect_attempt = 0;
#endif

void setup() {
  Serial.begin(115200);
  board.begin();

#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.begin();
#endif

#ifdef DISPLAY_CLASS
  DisplayDriver* disp = NULL;
  if (display.begin()) {
    disp = &display;
    disp->startFrame();
  #ifdef ST7789
    disp->setTextSize(2);
  #endif
    disp->drawTextCentered(disp->width() / 2, 28, "Loading...");
    disp->endFrame();
  }
#endif

  if (!radio_init()) { halt(); }

  fast_rng.begin(radio_driver.getRngSeed());

#if MESHCORE_LORA_OTA
  // Genuine earliest-boot-phase preflight, called strictly BEFORE
  // store.begin()/the_mesh.begin() below ever touch identity/prefs/
  // migration storage -- see otaBoardEarlyBootTrialOrUnknown()'s doc
  // comment. Only a genuinely qualified board whose persisted OTA state
  // record carries POSITIVE, already-bootloader-verified CONFIRMED
  // evidence AND a real fresh baseline proof, or a stock board proves a
  // fresh valid SDK/image and no install intent, reports false (allow).
  // Other cases -- unproven stock device, no qualified install history,
  // active/ambiguous/failed trial, CONFIRMED-without-fresh-proof, or an
  // OTA=1 build with no board-specific backend linked at all -- reports
  // true (block) -- "not currently mid-trial" is NOT the same as
  // "positively proven safe".
  const bool ota_allow_destructive_boot_writes = !otaBoardEarlyBootTrialOrUnknown();
  // Format permission and identity-generation permission are TWO FURTHER
  // SEPARATE, INDEPENDENTLY-VERIFIED permits -- not aliases of
  // ota_allow_destructive_boot_writes (ordinary userdata-write
  // authority) or of each other, and not merely differently-named
  // copies of the same value. Each requires its own explicit,
  // independently verified factory/repair authority (a future
  // certified-baseline/host-certificate provider, separate owner)
  // that does not exist anywhere in this tree yet; until that
  // authority is wired, BOTH stay
  // honestly false for EVERY MESHCORE_LORA_OTA=1 boot -- including a
  // genuinely Normal (userdata-write-permitted) boot. Normal userdata-
  // write evidence alone does not grant filesystem-format authority or
  // identity-generation authority.
  const bool ota_allow_format = false;
  const bool ota_allow_identity_generation = false;
#else
  const bool ota_allow_destructive_boot_writes = true;
  const bool ota_allow_format = true;
  const bool ota_allow_identity_generation = true;
#endif

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  // InternalFileSystem::begin() (and this repo's CustomLFS::begin()) both
  // override Adafruit_LittleFS's own begin() to erase/format the whole
  // flash region on a failed mount. Adafruit_LittleFS::begin() is public
  // and non-virtual, so an explicit base-class-qualified call statically
  // bypasses that override entirely (mount-only, zero format risk) without
  // touching either third-party/vendored file. During a trial/unknown boot
  // we must use that mount-only path so a corrupt/blank filesystem can
  // never be destructively reformatted before a failed OTA trial has a
  // chance to roll back with userdata intact; a normal boot keeps the
  // original legacy format-on-fail behaviour unchanged. Gated on
  // ota_allow_format (a SEPARATE permit from ordinary userdata-write
  // authority -- see its doc comment above): filesystem FORMAT authority
  // is never granted merely because userdata writes are Normal.
  bool internalfs_ok = ota_fs_mount::mountTrialSafe(
    ota_allow_format,
    [](){ return InternalFS.Adafruit_LittleFS::begin(); },
    [](){ return InternalFS.begin(); });
  #if defined(QSPIFLASH)
    // NOTE: the currently-approved MESHCORE_LORA_OTA=1 build target
    // (Xiao_nrf52_companion_radio_usb / SenseCap_Solar_companion_radio_usb)
    // does NOT define QSPIFLASH -- it uses EXTRAFS (this repo's CustomLFS,
    // fixed above via the same base-class-qualified mount-only call), so
    // this branch is not on that board's actual boot path today. It only
    // matters if/when QSPIFLASH is ever combined with MESHCORE_LORA_OTA=1
    // (e.g. a future BLE+OTA env). CustomLFS_QSPIFlash::begin() performs
    // QSPI peripheral init, chip detection, mount AND format-on-fail
    // atomically inside one call with no public non-destructive mount path
    // and no separable init step (pinned third-party library, not vendored
    // in-repo, outside our granted edit scope to patch). There is nothing
    // safe to call during a trial/unknown boot -- even the very first
    // mount attempt may format on failure -- so we must not call begin()
    // at all; the QSPI-backed filesystem is simply unavailable/degraded
    // for this boot instead. Gated on ota_allow_format for the same
    // reason as internalfs_ok above.
    bool qspiflash_ok = ota_fs_mount::mountOrDegradeIfDestructiveWritesDisallowed(
      ota_allow_format,
      [](){ return QSPIFlash.begin(); });
    if (!qspiflash_ok) {
      // debug output might not be available at this point, might be too early. maybe should fall back to InternalFS here?
      MESH_DEBUG_PRINTLN("CustomLFS_QSPIFlash: failed to initialize (or skipped: trial/unknown boot cannot risk its format-on-fail mount)");
    } else {
      MESH_DEBUG_PRINTLN("CustomLFS_QSPIFlash: initialized successfully");
    }
    bool filesystem_ok = internalfs_ok && qspiflash_ok;
  #else
  #if defined(EXTRAFS)
      // Same explicit-base-class-qualification mount-only fix as InternalFS
      // above: this repo's CustomLFS::begin() also overrides
      // Adafruit_LittleFS::begin() with an erase-and-format-on-fail retry.
      // Gated on ota_allow_format (separate permit, see above).
      bool extrafs_ok = ota_fs_mount::mountTrialSafe(
        ota_allow_format,
        [](){ return ExtraFS.Adafruit_LittleFS::begin(); },
        [](){ return ExtraFS.begin(); });
  #else
      bool extrafs_ok = true;
  #endif
    bool filesystem_ok = internalfs_ok && extrafs_ok;
  #endif
  store.begin(ota_allow_destructive_boot_writes, ota_allow_format);
  the_mesh.begin(
    #ifdef DISPLAY_CLASS
        disp != NULL
    #else
        false
    #endif
    , ota_allow_destructive_boot_writes
    , ota_allow_identity_generation
  );
  #if MESHCORE_LORA_OTA
    // radio_init() already succeeded above (or we halt()ed before reaching
    // here), so radio_ready is genuinely true at this point -- not an
    // assumed placeholder; filesystem_ok is the real begin() result(s)
    // captured just above, not an unconditional true.
    the_mesh.setOtaTrialBootHealthSignals(true, filesystem_ok);
  #endif
#elif defined(RP2040_PLATFORM)
  // arduino-pico's LittleFS.begin(bool formatOnFail = false) already
  // defaults to a non-destructive mount-only attempt (no call-site change
  // needed here): this call was never auto-formatting on a failed mount,
  // trial/unknown or not, so it's already trial-safe as written.
  bool filesystem_ok = LittleFS.begin();
  store.begin(ota_allow_destructive_boot_writes, ota_allow_format);
  the_mesh.begin(
    #ifdef DISPLAY_CLASS
        disp != NULL
    #else
        false
    #endif
    , ota_allow_destructive_boot_writes
    , ota_allow_identity_generation
  );
  #if MESHCORE_LORA_OTA
    the_mesh.setOtaTrialBootHealthSignals(true, filesystem_ok);
  #endif
#elif defined(ESP32)
  // SPIFFS.begin(bool formatOnFail=false, ...) exposes the format-on-fail
  // switch directly as its own public parameter (unlike the InternalFS/
  // CustomLFS backends above), so the fix here is simply to stop always
  // passing the literal `true` and instead gate it on ota_allow_format
  // (a SEPARATE permit from ordinary userdata-write authority -- see its
  // doc comment above): filesystem FORMAT authority is never granted
  // merely because userdata writes are Normal.
  bool filesystem_ok = SPIFFS.begin(ota_allow_format);
  store.begin(ota_allow_destructive_boot_writes, ota_allow_format);
  the_mesh.begin(
    #ifdef DISPLAY_CLASS
        disp != NULL
    #else
        false
    #endif
    , ota_allow_destructive_boot_writes
    , ota_allow_identity_generation
  );
  #if MESHCORE_LORA_OTA
    the_mesh.setOtaTrialBootHealthSignals(true, filesystem_ok);
  #endif
#else
  #error "need to define filesystem"
#endif

// add bluetooth interface
#if defined(BLE_PIN_CODE)
  bluetooth_interface.begin(BLE_NAME_PREFIX, the_mesh.getNodePrefs()->node_name, the_mesh.getBLEPin());
  interface_manager.addInterface(InterfaceType::Bluetooth, &bluetooth_interface);
#endif

// add wifi interface
#ifdef WIFI_SSID
  board.setInhibitSleep(true);   // prevent sleep when WiFi is active
  WiFi.setAutoReconnect(true);

  WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info){
      if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
          WIFI_DEBUG_PRINTLN("WiFi disconnected. Flagging for reconnect...");
          wifi_needs_reconnect = true;
      } else if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) {
          WIFI_DEBUG_PRINTLN("WiFi connected successfully!");
          wifi_needs_reconnect = false;
      }
  });

  WiFi.begin(WIFI_SSID, WIFI_PWD);
  wifi_interface.begin(TCP_PORT);
  interface_manager.addInterface(InterfaceType::WiFi, &wifi_interface);
#endif

// add usb interface
#if defined(ENABLE_USB_INTERFACE)
  usb_serial_interface.begin(Serial);
  interface_manager.addInterface(InterfaceType::USB, &usb_serial_interface);
#endif

// add ethernet interface
#if defined(ETHERNET_ENABLED)
  ethernet_interface.begin();
  interface_manager.addInterface(InterfaceType::Ethernet, &ethernet_interface);
#endif

// add hardware serial interface
#if defined(SERIAL_RX)
  companion_serial.setPins(SERIAL_RX, SERIAL_TX);
  companion_serial.begin(115200);
  hardware_serial_interface.begin(companion_serial);
  interface_manager.addInterface(InterfaceType::HardwareSerial, &hardware_serial_interface);
#endif

  the_mesh.startInterface(interface_manager);
  sensors.begin();

#if ENV_INCLUDE_GPS == 1
  the_mesh.applyGpsPrefs();
#endif

#ifdef DISPLAY_CLASS
  ui_task.begin(disp, &sensors, the_mesh.getNodePrefs());  // still want to pass this in as dependency, as prefs might be moved
#endif

  board.onBootComplete();
}

void loop() {
  the_mesh.loop();
  interface_manager.loop();
  sensors.loop();
#ifdef DISPLAY_CLASS
  ui_task.loop();
#endif
  rtc_clock.tick();
#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.loop();
#endif

#if defined(ESP32) && defined(WIFI_SSID)
  // Safely attempt to reconnect every 10 seconds if flagged
  if (wifi_needs_reconnect && (millis() - last_wifi_reconnect_attempt > 10000)) {
    WIFI_DEBUG_PRINTLN("Attempting manual WiFi reconnect...");
    WiFi.disconnect();
    WiFi.reconnect();
    last_wifi_reconnect_attempt = millis();
  }
#endif

#if MESHCORE_LORA_OTA
  // Trial-boot health tick runs LAST, only after every other real outer-
  // loop service for this pass has actually executed (mesh dispatch,
  // every interface, sensors/UI, RTC, the external watchdog, and WiFi
  // reconnect) -- confirming health before those services ran this same
  // pass could latch a false-healthy outcome even if one of them
  // silently failed or stalled earlier in the tick. Must also run BEFORE
  // the deep-sleep decision below, since MyMesh::hasPendingWork() must
  // see an up-to-date isTrialActive() this same pass.
  the_mesh.tickOtaTrialHealth();
#endif

  if (!the_mesh.hasPendingWork()) {
#if defined(NRF52_PLATFORM)
    board.sleep(0); // nrf ignores seconds param, sleeps whenever possible
#endif
  }
}
