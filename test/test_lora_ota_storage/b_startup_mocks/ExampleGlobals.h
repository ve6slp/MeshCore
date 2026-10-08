#pragma once

#include <Arduino.h>
#include <string>
#include <vector>
#include "Adafruit_LittleFS.h"
#include <helpers/IdentityStore.h>

namespace b_example_fixture {

struct Halt {};
struct State {
  std::vector<std::string> events;
  bool radio_ok = true, normal_proven = true, pending = false, trial_blocks_sleep = false;
  bool radio_healthy = true;
  bool radio_unavailable = false, identity_unavailable = false, writes_disallowed = false;
  bool health_radio = false, health_fs = false, identity_confirmed = false, boot_complete = false;
  bool store_writable = false, store_format_permitted = false, generation_permitted = false;
  int generated = 0, radio_seeds = 0, preflights = 0;
};

inline mesh::LocalIdentity generateIdentity(State& state) {
  ++state.generated;
  mesh::LocalIdentity identity;
  uint8_t bytes[PUB_KEY_SIZE + PRV_KEY_SIZE];
  memset(bytes, 0x42, sizeof(bytes));
  identity.readFrom(bytes, sizeof(bytes));
  return identity;
}

struct SerialPort : Stream {
  void begin(int) {}
  void println() {}
  template<typename T> void println(T) {}
};

struct Board {
  State* state;
  void begin() {}
  void loop() { state->events.push_back("board"); }
  void sleep(int) { state->events.push_back("sleep"); }
  void onBootComplete() { state->boot_complete = true; }
};

struct Radio {
  State* state;
  uint32_t getRngSeed() { ++state->radio_seeds; return 123; }
  bool probeDriverStatus() { return state->radio_healthy; }
};
struct Rng { void begin(uint32_t) {} };

struct Service {
  State* state;
  const char* label;
  void begin() {}
  void loop() { state->events.push_back(label); }
  void tick() { state->events.push_back(label); }
};
struct Wifi {
  State* state;
  void begin(const char*, const char*) {}
  void disconnect() { state->events.push_back("wifi.disconnect"); }
  void reconnect() { state->events.push_back("wifi.reconnect"); }
  int status() { return 0; }
};
struct WifiInterface { void begin(int) {} };
enum class InterfaceType { WiFi };
struct Interfaces : Service {
  void addInterface(InterfaceType, WifiInterface*) {}
};

struct Prefs {
  uint32_t ble_pin = 0;
  char node_name[32] = "fixture", wifi_ssid[33] = "", wifi_pwd[64] = "";
  bool wifi_enabled = false, powersaving_enabled = true;
};

struct Store {
  State* state;
  Adafruit_LittleFS* fs;
  identity_io::LoadStatus loadMainIdentityStatus(mesh::LocalIdentity& identity, bool mounted) {
    IdentityStore store(*fs, "");
    return store.loadWithStatus("_main", identity, mounted);
  }
  void begin(bool writable = true, bool format = true, bool ready = true) {
    state->store_writable = writable && ready;
    state->store_format_permitted = format && ready;
    if (writable && ready) fs->mkdir("/bl");
  }
  void disallowDestructiveWrites() { state->store_writable = false; }
};

struct Mesh {
  State* state;
  Adafruit_LittleFS* fs;
  mesh::LocalIdentity self_id;
  Prefs prefs;
  void begin(bool writable, bool generation, identity_io::LoadStatus status = identity_io::LoadStatus::Unchecked) {
    state->generation_permitted = generation;
    if (status == identity_io::LoadStatus::Unchecked) {
      IdentityStore store(*fs, "");
      status = store.load("_main", self_id) ? identity_io::LoadStatus::Loaded : identity_io::LoadStatus::Absent;
    }
    if (status != identity_io::LoadStatus::Loaded && generation) {
      self_id = generateIdentity(*state);
      IdentityStore store(*fs, "");
      if (writable) state->identity_confirmed = store.save("_main", self_id);
    }
  }
  void begin(FILESYSTEM*) {}
  Prefs* getNodePrefs() { return &prefs; }
  void setBLEPin(uint32_t) {}
  void startInterface(Interfaces&) {}
  void loop() { state->events.push_back("mesh"); }
  bool hasPendingWork() { return state->pending; }
  bool millisHasNowPassed(uint32_t) { return true; }
  void tickOtaTrialHealth() {
    state->events.push_back("trial");
    if (state->trial_blocks_sleep) state->pending = true;
  }
  void setOtaTrialBootHealthSignals(bool radio, bool filesystem) {
    state->health_radio = radio; state->health_fs = filesystem;
  }
  void notifyRadioUnavailableForDispatch() { state->radio_unavailable = true; }
  void notifyIdentityUnavailableForDispatch() { state->identity_unavailable = true; }
  void notifyDestructiveWritesDisallowed() { state->writes_disallowed = true; }
  void notifyOtaTrialIdentityLoadFault() {}
  void notifyOtaIdentityConfirmedLoaded(bool loaded) { state->identity_confirmed = loaded; }
  void handleCommand(uint32_t, const char*, char*, bool) {}
  void sendSelfAdvertisement(uint32_t, bool) {}
};

}  // namespace b_example_fixture
