#pragma once

#include <MeshCore.h>
#include <Identity.h>
#include <Packet.h>
#include <Utils.h>
#include <string.h>
#include <helpers/ota/OtaMeshHooks.h>

#if MESHCORE_LORA_OTA
#include <helpers/ota/OtaFirmwareIntegration.h>
#endif

namespace mesh {

struct RadioDriverFaultDiagnostic;

/**
 * \brief  Abstraction of local/volatile clock with Millisecond granularity.
*/
class MillisecondClock {
public:
  virtual unsigned long getMillis() = 0;
};

/**
 * \brief  Abstraction of this device's packet radio.
*/
class Radio {
public:
  virtual void begin() { }

  /**
   * \brief  polls for incoming raw packet.
   * \param  bytes  destination to store incoming raw packet.
   * \param  sz   maximum packet size allowed.
   * \returns 0 if no incoming data, otherwise length of complete packet received.
  */
  virtual int recvRaw(uint8_t* bytes, int sz) = 0;

  /**
   * \returns  estimated transmit air-time needed for packet of 'len_bytes', in milliseconds.
  */
  virtual uint32_t getEstAirtimeFor(int len_bytes) = 0;

  virtual float packetScore(float snr, int packet_len) = 0;

  /**
   * \brief  starts the raw packet send. (no wait)
   * \param  bytes   the raw packet data
   * \param  len  the length in bytes
   * \returns true if successfully started
  */
  virtual bool startSendRaw(const uint8_t* bytes, int len) = 0;

  /**
   * \returns true if the previous 'startSendRaw()' completed successfully.
  */
  virtual bool isSendComplete() = 0;

  /**
   * \brief  a hook for doing any necessary clean up after transmit.
  */
  virtual void onSendFinished() = 0;

  /**
   * \brief  do any processing needed on each loop cycle
   */
  virtual void loop() { }

  virtual int getNoiseFloor() const { return 0; }

  virtual void triggerNoiseFloorCalibrate(int threshold) { }

  virtual void setCADEnabled(bool enable) { }

  virtual void resetAGC() { }

  virtual bool isInRecvMode() const = 0;

  /**
   * \returns  true unless the radio DRIVER itself has just reported a
   *           genuine failure on its most recent real operation (i.e. the
   *           return status of an actual startReceive()/readData()/
   *           startTransmit() call that was already being performed for
   *           ordinary traffic -- never a synthetic/extra probe query).
   *           A momentary, expected state transition (e.g. leaving Rx
   *           mode to transmit) is NOT itself a driver failure and must
   *           not make this false; only an explicit non-success return
   *           code from the underlying radio library does. Implementations
   *           that have no way to observe this default to always healthy
   *           (true), so existing radio backends are unaffected unless
   *           they choose to opt in.
  */
  virtual bool isDriverHealthy() const { return true; }

  /**
   * \returns  a lifetime count, incrementing modulo 2^32, of every recorded
   *           driver-operation failure ever recorded (see
   *           RadioDriverHealthLatch::faultCount()). Comparing two
   *           readings taken at different times tells a caller whether
   *           ANY real failure happened in between, even if the LATEST
   *           isDriverHealthy()/probeDriverStatus() result is healthy --
   *           needed because a later, unrelated successful call would
   *           otherwise silently mask an earlier failure within the same
   *           pass. Implementations with no such counter default to 0
   *           (never advances), so existing radio backends are
   *           unaffected unless they choose to opt in.
  */
  virtual uint32_t driverFaultCount() const { return 0; }

  // Optional passive public history. Unsupported implementations must not
  // fabricate an empty/healthy diagnostic; the caller maps false to UNSUPPORTED.
  virtual bool getDriverFaultDiagnostic(RadioDriverFaultDiagnostic&) const { return false; }

  /**
   * \returns  true only after a genuine, freshly-taken driver status
   *           check reports the radio healthy right now -- an ACTIVE,
   *           bounded probe (e.g. reading a real hardware error-flag
   *           register), not merely the passively-latched result of
   *           whichever ordinary send/receive op happened to run last.
   *           Implementations that have no such active probe available
   *           default to isDriverHealthy()'s existing passive/reactive
   *           signal, so this is safe to call unconditionally even where
   *           no real probe exists yet.
  */
  virtual bool probeDriverStatus() { return isDriverHealthy(); }

  /**
   * \returns  true if the radio is currently mid-receive of a packet.
  */
  virtual bool isReceiving() { return false; }

  virtual float getLastRSSI() const { return 0; }
  virtual float getLastSNR() const { return 0; }
};

/**
 * \brief  An abstraction for managing instances of Packets (eg. in a static pool),
 *        and for managing the outbound packet queue.
*/
class PacketManager {
public:
  // Shared threshold (buffers) below which OTA traffic must yield to
  // ordinary traffic. This single constant is enforced at FIVE distinct
  // points so that no single path can starve the pool out from under the
  // ordinary sender / raw radio ingress / delayed-RX / relay paths:
  //  1. OTA's own outbound bulk allocation (is_ota_bulk=true, allocNew()
  //     below fails closed -- see StaticPoolPacketManager::allocNew()).
  //  2/3. Raw radio ingress + delayed-RX: Dispatcher::checkRecv() frees an
  //     incoming packet immediately, without processing it, the instant it
  //     is classified (post-parse) as OTA and accepting it would leave the
  //     pool at or below this reserve (see Dispatcher::checkRecv()).
  //  4. Relay: Dispatcher::processRecvPacket() drops (instead of queueing
  //     for retransmit/relay) an OTA packet under the same condition, so a
  //     relayed OTA packet can never occupy a buffer for the (potentially
  //     long, duty-budget-gated) duration it sits in the outbound queue
  //     awaiting airtime (see Dispatcher::processRecvPacket()).
  //  5. Locally-originated raw packet injection (CMD_SEND_RAW_PACKET):
  //     the payload type is not known until after allocNew(false)+parse,
  //     exactly like raw radio ingress above, so the caller must re-check
  //     and release the packet post-parse under the same condition instead
  //     of queueing it for send (see MyMesh's CMD_SEND_RAW_PACKET handler).
  //     Without this, OTA traffic sent via this path bypasses the reserve
  //     entirely (since allocNew() only fails-closed when is_ota_bulk=true
  //     is passed at allocation time) and can exhaust the whole pool,
  //     starving even CMD_SEND_SELF_ADVERT's own allocation.
  // OTA is inherently retry/repair-capable, so dropping under pressure at
  // any of these points is safe; ordinary (non-OTA) traffic is NEVER
  // subject to this reserve check.
  static constexpr int kOtaAllocReserve = 4;

  // `is_ota_bulk` marks an allocation as OTA's own outbound bulk traffic
  // (chunks/census/repair/etc, see Mesh::createOtaData()). Implementations
  // should fail closed (return nullptr) for these once the free pool is at
  // or below a small reserve, so a burst of background OTA traffic can
  // never starve the ordinary sender / raw radio ingress / delayed-RX /
  // relay paths (which all call allocNew(false), the default) of buffers.
  virtual Packet* allocNew(bool is_ota_bulk = false) = 0;
  virtual void free(Packet* packet) = 0;

  // Returns true if the packet was actually queued, false if it was
  // dropped (e.g. send queue full) -- in which case the implementation
  // must have already freed it back to the pool. Callers that need to
  // surface enqueue failure to a user/host (rather than silently
  // reporting success for a packet that was never actually queued for
  // transmission) must check this return value; see
  // Dispatcher::sendPacket() / Mesh::sendFlood().
  virtual bool queueOutbound(Packet* packet, uint8_t priority, uint32_t scheduled_for) = 0;
  // by priority; when out_priority is non-null, the priority of the
  // packet actually popped is written back through it (needed so callers
  // that must requeue a popped-but-not-yet-sent packet, e.g. due to
  // insufficient airtime budget, can preserve its original queue priority
  // instead of guessing/collapsing it).
  virtual Packet* getNextOutbound(uint32_t now, uint8_t* out_priority = nullptr) = 0;
  virtual int getOutboundCount(uint32_t now) const = 0;
  virtual int getOutboundTotal() const = 0;
  virtual int getFreeCount() const = 0;
  virtual Packet* getOutboundByIdx(int i) = 0;
  // Scheduled-for timestamp of the still-queued entry at index i, used to
  // filter out not-yet-ready (future-scheduled) entries when scanning the
  // full queue for readiness (see Dispatcher::hasQueuedNormalTraffic()/
  // hasQueuedOtaTraffic()).
  virtual uint32_t getOutboundScheduledForByIdx(int i) const = 0;
  virtual Packet* removeOutboundByIdx(int i) = 0;
  virtual void queueInbound(Packet* packet, uint32_t scheduled_for) = 0;
  virtual Packet* getNextInbound(uint32_t now) = 0;
};

typedef uint32_t  DispatcherAction;

#define ACTION_RELEASE           (0)
#define ACTION_MANUAL_HOLD       (1)
#define ACTION_RETRANSMIT(pri)   (((uint32_t)1 + (pri))<<24)
#define ACTION_RETRANSMIT_DELAYED(pri, _delay)  ((((uint32_t)1 + (pri))<<24) | (_delay))

#define ERR_EVENT_FULL              (1 << 0)
#define ERR_EVENT_CAD_TIMEOUT       (1 << 1)
#define ERR_EVENT_STARTRX_TIMEOUT   (1 << 2)

/**
 * \brief  The low-level task that manages detecting incoming Packets, and the queueing
 *      and scheduling of outbound Packets.
*/
class Dispatcher {
  Packet* outbound;  // current outbound packet
  uint8_t outbound_priority;  // priority the outbound packet was originally queued with
  unsigned long outbound_expiry, outbound_start, total_air_time, rx_air_time;
#if MESHCORE_LORA_OTA
  bool outbound_is_ota;
  meshcore::ota::protocol::OtaAirtimeCategory outbound_ota_category;
  mesh::ota::OtaFirmwareIntegration dispatcher_ota;
  mesh::ota::OtaFirmwareIntegration* active_ota;
  uint32_t tx_timeout_count, ota_accounting_failure_count;
#endif
  unsigned long next_tx_time;
  unsigned long cad_busy_start;
  unsigned long radio_nonrx_start;
  unsigned long next_floor_calib_time, next_agc_reset_time;
  bool  prev_isrecv_mode;
  uint32_t n_sent_flood, n_sent_direct;
  uint32_t n_recv_flood, n_recv_direct;
  unsigned long tx_budget_ms;
  unsigned long last_budget_update;
  unsigned long duty_cycle_window_ms;

  void processRecvPacket(Packet* pkt);
  void updateTxBudget();

protected:
  PacketManager* _mgr;
  Radio* _radio;
  MillisecondClock* _ms;
  uint16_t _err_flags;

  Dispatcher(Radio& radio, MillisecondClock& ms, PacketManager& mgr)
    : _radio(&radio), _ms(&ms), _mgr(&mgr)
  {
    outbound = NULL;
    outbound_priority = 0;
#if MESHCORE_LORA_OTA
    outbound_is_ota = false;
    outbound_ota_category = meshcore::ota::protocol::OtaAirtimeCategory::Control;
    active_ota = &dispatcher_ota;
    tx_timeout_count = ota_accounting_failure_count = 0;
#endif
    total_air_time = rx_air_time = 0;
    next_tx_time = ms.getMillis();
    cad_busy_start = 0;
    next_floor_calib_time = next_agc_reset_time = 0;
    _err_flags = 0;
    radio_nonrx_start = 0;
    prev_isrecv_mode = true;
    tx_budget_ms = 0;
    last_budget_update = 0;
    duty_cycle_window_ms = 3600000;
  }

  virtual DispatcherAction onRecvPacket(Packet* pkt) = 0;

  virtual void logRxRaw(float snr, float rssi, const uint8_t raw[], int len) { }   // custom hook

  virtual void logRx(Packet* packet, int len, float score) { }   // hooks for custom logging
  virtual void logTx(Packet* packet, int len) { }
  virtual void logTxFail(Packet* packet, int len) { }
  virtual const char* getLogDateTime() { return ""; }

  virtual float getAirtimeBudgetFactor() const;
  virtual int calcRxDelay(float score, uint32_t air_time) const;
  virtual uint32_t getCADFailRetryDelay() const;
  virtual uint32_t getCADFailMaxDuration() const;
  virtual int getInterferenceThreshold() const { return 0; }    // disabled by default
  virtual bool getCADEnabled() const { return false; }    // hardware CAD disabled by default
  virtual int getAGCResetInterval() const { return 0; }    // disabled by default
  virtual unsigned long getDutyCycleWindowMs() const { return 3600000; }

public:
  void begin();
  void loop();

  Packet* obtainNewPacket(bool is_ota_bulk = false);
  void releasePacket(Packet* packet);
  // Returns true if the packet was actually queued for transmission,
  // false if it was invalid or dropped (queue full) -- in either failure
  // case the packet has already been freed back to the pool. Callers
  // that unconditionally report success without checking this can end up
  // reporting an ordinary-looking OK for a packet that never actually got
  // queued (see Mesh::sendFlood()).
  bool sendPacket(Packet* packet, uint8_t priority, uint32_t delay_millis=0);
#if MESHCORE_LORA_OTA
  bool hasQueuedNormalTraffic();
  bool hasQueuedOtaTraffic();
  void attachOtaIntegration(mesh::ota::OtaFirmwareIntegration* integration) {
    active_ota = integration != nullptr ? integration : &dispatcher_ota;
  }
  mesh::ota::OtaFirmwareIntegration& getDispatcherOtaIntegration() { return *active_ota; }
  const mesh::ota::OtaFirmwareIntegration& getDispatcherOtaIntegration() const { return *active_ota; }
#endif

  unsigned long getTotalAirTime() const { return total_air_time; }
  unsigned long getReceiveAirTime() const {return rx_air_time; }
  unsigned long getRemainingTxBudget() const { return tx_budget_ms; }
#if MESHCORE_LORA_OTA
  bool setOtaAirtimeDutyCyclePercent(float percent) { return active_ota->setDutyCyclePercent(percent); }
  float getOtaAirtimeDutyCyclePercent() const { return active_ota->dutyCyclePercent(); }
  unsigned long getRemainingOtaAirtimeBudget(unsigned long now_ms) const {
    uint32_t used = active_ota->airtimeLimiter().storedUsageMs(now_ms);
    uint32_t budget = active_ota->dutyBudgetMs();
    return used >= budget ? 0 : budget - used;
  }
  mesh::ota::FirmwareOtaStatus getOtaStatus(unsigned long now_ms) const { return active_ota->status(now_ms); }
  uint32_t getTxTimeoutCount() const { return tx_timeout_count; }
  uint32_t getOtaAccountingFailureCount() const { return ota_accounting_failure_count; }
#endif
  uint32_t getNumSentFlood() const { return n_sent_flood; }
  uint32_t getNumSentDirect() const { return n_sent_direct; }
  uint32_t getNumRecvFlood() const { return n_recv_flood; }
  uint32_t getNumRecvDirect() const { return n_recv_direct; }
  void resetStats() {
    n_sent_flood = n_sent_direct = n_recv_flood = n_recv_direct = 0;
    _err_flags = 0;
  }

  // helper methods
  bool millisHasNowPassed(unsigned long timestamp) const;
  unsigned long futureMillis(int millis_from_now) const;

  // True while a send is genuinely in flight (i.e. between checkSend()
  // starting a real transmit and its onSendFinished()/expiry). Used by
  // OTA trial-health so it can tell "actively transmitting" apart from
  // "stuck out of Rx for no reason" instead of guessing from a fixed
  // timeout alone.
  bool isSendInProgress() const { return outbound != nullptr; }
  // The real, per-packet-airtime-derived (already includes a 50% margin,
  // see checkSend()) deadline of the current in-flight send, if any. Only
  // meaningful while isSendInProgress() is true.
  unsigned long getCurrentSendDeadlineMs() const { return outbound_expiry; }
  // Timestamp (getMillis() domain) of the last time the radio left Rx
  // mode; used, together with isSendInProgress()/getCurrentSendDeadlineMs(),
  // to bound "stuck non-Rx" checks by the ACTUAL expected duration of
  // whatever is currently happening, rather than a single fixed constant
  // that can misfire against a legitimately long transmit.
  unsigned long getRadioNonRecvSinceMs() const { return radio_nonrx_start; }

  bool tryParsePacket(Packet* pkt, const uint8_t* raw, int len);

private:
  Packet* readReceivedPacket(float& score, uint32_t& air_time);
  void checkRecv();
  void checkSend();
};

}
