#include <Arduino.h>   // needed for PlatformIO
#include <Mesh.h>

#include "MyMesh.h"
// Pure templates, no Arduino/OTA-feature dependency: the trial-safe mount
// and identity-boot call sites below apply unconditionally (even when
// MESHCORE_LORA_OTA is compiled out, ota_allow_destructive_boot_writes is
// simply always true, matching legacy behaviour byte-for-byte) -- see
// examples/companion_radio/main.cpp's identical usage.
#include "helpers/ota/OtaTrialSafeFilesystemMount.h"
#include "helpers/ota/OtaTrialSafeIdentityBoot.h"

#if MESHCORE_LORA_OTA
// Declared here (not exposed via MyMesh.h), same reasoning as
// examples/companion_radio/main.cpp: must be queried strictly BEFORE
// store.load()/the_mesh.begin() ever touch identity/filesystem state.
bool otaBoardEarlyBootTrialOrUnknown();
#endif


#ifdef DISPLAY_CLASS
  #include "UITask.h"
  static UITask ui_task(board, display);
#endif

#ifdef ETHERNET_ENABLED
  #define ETHERNET_CLI_BANNER "MeshCore Repeater CLI"
  #include <helpers/nrf52/EthernetCLI.h>
#endif

StdRNG fast_rng;
SimpleMeshTables tables;

MyMesh the_mesh(board, radio_driver, *new ArduinoMillis(), fast_rng, rtc_clock, tables);

void halt() {
  while (1) ;
}

static char command[160];
#ifdef ETHERNET_ENABLED
static char ethernet_command[160];
#endif

// For power saving
unsigned long POWERSAVING_FIRSTSLEEP_SECS = 120; // The first sleep (if enabled) from boot

#if defined(PIN_USER_BTN) && defined(_SEEED_SENSECAP_SOLAR_H_)
static unsigned long userBtnDownAt = 0;
#define USER_BTN_HOLD_OFF_MILLIS 1500
#endif

void setup() {
  Serial.begin(115200);
  delay(1000);

  board.begin();

#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.begin();
#endif

#if defined(MESH_DEBUG) && defined(NRF52_PLATFORM)
  // give some extra time for serial to settle so
  // boot debug messages can be seen on terminal
  delay(5000);
#endif

#ifdef DISPLAY_CLASS
  if (display.begin()) {
    display.startFrame();
    display.setCursor(0, 0);
    display.print("Please wait...");
    display.endFrame();
  }
#endif

  // A failed radio_init() previously halt()ed here, stranding the serial/
  // CLI/maintenance/OTA-trial-health path along with RF dispatch -- per
  // the same degraded-lifecycle contract already proven on this board's
  // identity-load failure below, keep setup()/loop() reachable instead:
  // notifyRadioUnavailableForDispatch() suppresses MyMesh::begin()'s/
  // loop()'s RF-touching operations (see MyMesh.h's _radio_available_
  // doc comment), and fast_rng falls back to a millis()-based seed
  // rather than calling getRngSeed() against a known-failed radio.
  const bool radio_ok = radio_init();
  if (!radio_ok) {
    MESH_DEBUG_PRINTLN("Radio init failed! Continuing in degraded (maintenance-only) mode.");
    the_mesh.notifyRadioUnavailableForDispatch();
  }

  fast_rng.begin(radio_ok ? radio_driver.getRngSeed() : (uint32_t)millis());

#if MESHCORE_LORA_OTA
  // Same contract as examples/companion_radio/main.cpp: "not currently
  // mid-trial" is NOT the same as "positively proven safe" -- every case
  // except a positively verified stock boot or genuine qualified
  // baseline reports true (block ordinary filesystem writes this boot).
  const bool ota_allow_destructive_boot_writes = !otaBoardEarlyBootTrialOrUnknown();
  if (!ota_allow_destructive_boot_writes) {
    // Same policy MyMesh's own identity-generation path below already
    // honours -- also propagate it to loop()'s acl.save(_fs) (contacts
    // ACL persistence is a destructive write too, see
    // _ota_destructive_writes_disallowed_'s doc comment in MyMesh.h).
    the_mesh.notifyDestructiveWritesDisallowed();
  }
#else
  const bool ota_allow_destructive_boot_writes = true;
#endif
  // Format permission is a separate, independently-verified permit, not
  // an alias of ota_allow_destructive_boot_writes -- see
  // examples/companion_radio/main.cpp's identical doc comment. No such
  // authority is wired anywhere in this tree yet, so it stays false for
  // every MESHCORE_LORA_OTA=1 boot.
#if MESHCORE_LORA_OTA
  const bool ota_allow_format = false;
#else
  const bool ota_allow_format = true;
#endif

  FILESYSTEM* fs;
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  // Mount-only during a trial/unknown boot (see OtaTrialSafeFilesystemMount.h)
  // so a corrupt/blank filesystem is never destructively reformatted
  // before a failed OTA trial has a chance to roll back with userdata
  // intact; a normal boot keeps the original legacy format-on-fail
  // behaviour unchanged.
  bool filesystem_ok = ota_fs_mount::mountTrialSafe(
    ota_allow_format,
    [](){ return InternalFS.Adafruit_LittleFS::begin(); },
    [](){ return InternalFS.begin(); });
  fs = &InternalFS;
  IdentityStore store(InternalFS, "");
#elif defined(ESP32)
  bool filesystem_ok = SPIFFS.begin(ota_allow_format);
  fs = &SPIFFS;
  IdentityStore store(SPIFFS, "/identity");
#elif defined(RP2040_PLATFORM)
  // arduino-pico's LittleFS.begin(bool formatOnFail = false) already
  // defaults to a non-destructive mount-only attempt.
  bool filesystem_ok = LittleFS.begin();
  fs = &LittleFS;
  IdentityStore store(LittleFS, "/identity");
  store.begin();
#else
  #error "need to define filesystem"
#endif
#if MESHCORE_LORA_OTA
  // Astra's correction: unlike companion_radio (whose main.cpp halt()s
  // on a failed radio_init(), making `true` always genuinely true by
  // the time this is reached), this board continues in degraded
  // (maintenance-only) mode on radio failure -- so the boot-health
  // signal fed into the shared trial evaluator must reflect the REAL
  // radio_ok result, never a literal `true`.
  the_mesh.setOtaTrialBootHealthSignals(radio_ok, filesystem_ok);
#endif
  bool identity_loaded = store.load("_main", the_mesh.self_id);
  if (!identity_loaded) {
#if MESHCORE_LORA_OTA
    // Same unconditional latch as examples/companion_radio/MyMesh.cpp's
    // begin(): a genuine load failure is recorded even on an ordinary
    // never-configured device, because a successful fresh generate+save
    // immediately below would otherwise make this boot indistinguishable
    // from a healthy one.
    the_mesh.notifyOtaTrialIdentityLoadFault();
#endif
    bool save_ok = false;
    // Astra's correction: generation itself must never run against a
    // known-failed radio -- target.cpp's radio_new_identity() draws its
    // entropy from RadioNoiseListener(radio), a REAL noise-floor read
    // over the same (possibly uninitialized) SPI radio object, never
    // fast_rng/millis. Folding `radio_ok` into the generation-permit
    // reuses the EXACT existing IdentityUnavailable contract (zero
    // generation, zero writes, self_id left unset, degraded-dispatch-
    // only) instead of inventing a second decision path or promoting
    // millis-seeded entropy into an identity.
#if MESHCORE_LORA_OTA
    // A verified stock boot permits ordinary writes, not replacement of an unreadable identity.
    const bool identity_generation_safe = false;
#else
    const bool identity_generation_safe = ota_allow_destructive_boot_writes && radio_ok;
#endif
    const ota_identity_boot::Outcome identity_outcome = ota_identity_boot::resolveIdentityTrialSafe(
        identity_generation_safe,
        [](){ return false; },  // load_fn: already known-failed above, never re-invoked.
        [&](){
          the_mesh.self_id = radio_new_identity();   // create new random identity
          int count = 0;
          while (count < 10 && (the_mesh.self_id.pub_key[0] == 0x00 || the_mesh.self_id.pub_key[0] == 0xFF)) {  // reserved id hashes
            the_mesh.self_id = radio_new_identity(); count++;
          }
        },
        [&](){ save_ok = store.save("_main", the_mesh.self_id); return save_ok; });
    if (identity_outcome == ota_identity_boot::Outcome::IdentityUnavailable) {
      // A failed load during a trial/unknown boot might merely be
      // transiently unreadable, not genuinely corrupt/absent -- the
      // ORIGINAL persisted secret must never be overwritten or
      // RAM-synthesized around. Perform ZERO generation and ZERO writes:
      // self_id is left at its default/unset value. Previously this
      // halted unconditionally (repeater had no equivalent of
      // companion_radio's `_identity_available_` degraded-dispatch
      // mode); now mirrors companion's exact pattern instead --
      // notifyIdentityUnavailableForDispatch() suppresses MyMesh::loop()'s
      // ordinary mesh dispatch (identity-dependent TX/signing/advert) and
      // begin()'s acl.load() for the rest of this boot, while leaving the
      // bounded serial/CLI/maintenance/trial-health path (and the
      // bootloader's own trial-rollback path on the next boot) reachable.
      MESH_DEBUG_PRINTLN("OTA trial/unknown boot: identity unavailable, running degraded (no mesh dispatch)");
#if MESHCORE_LORA_OTA
      the_mesh.notifyIdentityUnavailableForDispatch();
#endif
    }
#if MESHCORE_LORA_OTA
    // Only a genuinely PERSISTED fresh identity counts as "confirmed
    // loaded" -- a RAM-only one (not reachable here: the IdentityUnavailable
    // branch above handles the no-identity case, and generation
    // failure-to-save isn't possible without allow_destructive_boot_writes
    // being true, which is exactly when a save is actually attempted) is
    // never silently treated as durably bound. See
    // notifyOtaIdentityConfirmedLoaded()'s doc comment in MyMesh.h.
    the_mesh.notifyOtaIdentityConfirmedLoaded(identity_outcome == ota_identity_boot::Outcome::GeneratedAndSaved);
#endif
  } else {
#if MESHCORE_LORA_OTA
    the_mesh.notifyOtaIdentityConfirmedLoaded(true);
#endif
  }

  Serial.print("Repeater ID: ");
  mesh::Utils::printHex(Serial, the_mesh.self_id.pub_key, PUB_KEY_SIZE); Serial.println();

  command[0] = 0;
#ifdef ETHERNET_ENABLED
  ethernet_command[0] = 0;
#endif

  sensors.begin();

  the_mesh.begin(fs);

#ifdef DISPLAY_CLASS
  ui_task.begin(the_mesh.getNodePrefs(), FIRMWARE_BUILD_DATE, FIRMWARE_VERSION);
#endif

#ifdef ETHERNET_ENABLED
  ethernet_start_task();
#endif

  // send out initial zero hop Advertisement to the mesh
#if ENABLE_ADVERT_ON_BOOT == 1
  the_mesh.sendSelfAdvertisement(16000, false);
#endif

  board.onBootComplete();
}

void loop() {
  // Handle Serial CLI
  int len = strlen(command);
  while (Serial.available() && len < sizeof(command)-1) {
    char c = Serial.read();
    if (c != '\n') {
      command[len++] = c;
      command[len] = 0;
      Serial.print(c);
    }
    if (c == '\r') break;
  }
  if (len == sizeof(command)-1) {  // command buffer full
    command[sizeof(command)-1] = '\r';
  }

  if (len > 0 && command[len - 1] == '\r') {  // received complete line
    Serial.print('\n');
    command[len - 1] = 0;  // replace newline with C string null terminator
    char reply[160];
    reply[0] = 0;
#ifdef ETHERNET_ENABLED
    if (!ethernet_handle_command(command, reply)) {
      the_mesh.handleCommand(0, command, reply);
    }
#else
    the_mesh.handleCommand(0, command, reply);  // NOTE: there is no sender_timestamp via serial!
#endif
    if (reply[0]) {
      Serial.print("  -> "); Serial.println(reply);
    }

    command[0] = 0;  // reset command buffer
  }

#ifdef ETHERNET_ENABLED
  ethernet_loop_maintain();
  if (ethernet_read_line(ethernet_command, sizeof(ethernet_command))) {
    char reply[160];
    reply[0] = 0;
    if (!ethernet_handle_command(ethernet_command, reply)) {
      the_mesh.handleCommand(0, ethernet_command, reply);
    }
    ethernet_send_reply(reply);
    ethernet_command[0] = 0;
  }
#endif

#if defined(PIN_USER_BTN) && defined(_SEEED_SENSECAP_SOLAR_H_) && !defined(DISPLAY_CLASS)
  // Hold the user button to power off the SenseCAP Solar repeater.
  int btnState = digitalRead(PIN_USER_BTN);
  if (btnState == LOW) {
    if (userBtnDownAt == 0) {
      userBtnDownAt = millis();
    } else if ((unsigned long)(millis() - userBtnDownAt) >= USER_BTN_HOLD_OFF_MILLIS) {
      Serial.println("Powering off...");
      board.powerOff();  // does not return
    }
  } else {
    userBtnDownAt = 0;
  }
#endif

  the_mesh.loop();
  sensors.loop();
#ifdef DISPLAY_CLASS
  ui_task.loop();
#endif
  rtc_clock.tick();

#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.loop();
#endif

#if MESHCORE_LORA_OTA
  // Runs LAST, only after every other real outer-loop service for this
  // pass has actually executed, and BEFORE the deep-sleep decision below
  // -- see examples/companion_radio/main.cpp's identical placement/
  // rationale for tickOtaTrialHealth().
  the_mesh.tickOtaTrialHealth();
#endif

  if (the_mesh.getNodePrefs()->powersaving_enabled && !the_mesh.hasPendingWork()) {
#if defined(NRF52_PLATFORM)
    board.sleep(0); // nrf ignores seconds param, sleeps whenever possible
#else
    if (the_mesh.millisHasNowPassed(POWERSAVING_FIRSTSLEEP_SECS * 1000)) { // To check if it is time to sleep
      board.sleep(30); // Sleep. Wake up after a while or when receiving a LoRa packet
    }
#endif
  }
}
