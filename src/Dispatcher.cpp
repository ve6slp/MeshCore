#include "Dispatcher.h"

#if MESH_PACKET_LOGGING
  #include <Arduino.h>
#endif

#include <math.h>

namespace mesh {

#define MAX_RX_DELAY_MILLIS        32000  // 32 seconds
#define MIN_TX_BUDGET_RESERVE_MS   100    // min budget (ms) required before allowing next TX
#define MIN_TX_BUDGET_AIRTIME_DIV  2      // require at least 1/N of estimated airtime as budget before TX

#ifndef NOISE_FLOOR_CALIB_INTERVAL
  #define NOISE_FLOOR_CALIB_INTERVAL   2000     // 2 seconds
#endif

void Dispatcher::begin() {
  n_sent_flood = n_sent_direct = 0;
  n_recv_flood = n_recv_direct = 0;
  _err_flags = 0;
  radio_nonrx_start = _ms->getMillis();

  duty_cycle_window_ms = getDutyCycleWindowMs();
  float duty_cycle = 1.0f / (1.0f + getAirtimeBudgetFactor());
  tx_budget_ms = (unsigned long)(duty_cycle_window_ms * duty_cycle);
  last_budget_update = _ms->getMillis();

  _radio->begin();
  prev_isrecv_mode = _radio->isInRecvMode();
}

float Dispatcher::getAirtimeBudgetFactor() const {
  return 1.0;
}

void Dispatcher::updateTxBudget() {
  unsigned long now = _ms->getMillis();
  unsigned long elapsed = now - last_budget_update;

  float duty_cycle = 1.0f / (1.0f + getAirtimeBudgetFactor());
  unsigned long max_budget = (unsigned long)(getDutyCycleWindowMs() * duty_cycle);
  unsigned long refill = (unsigned long)(elapsed * duty_cycle);
  
  if (refill > 0) {
    tx_budget_ms += refill;
    if (tx_budget_ms > max_budget) {
      tx_budget_ms = max_budget;
    }
    last_budget_update = now;
  }
}

int Dispatcher::calcRxDelay(float score, uint32_t air_time) const {
  return (int) ((pow(10, 0.85f - score) - 1.0) * air_time);
}

uint32_t Dispatcher::getCADFailRetryDelay() const {
  return 200;
}
uint32_t Dispatcher::getCADFailMaxDuration() const {
  return 4000;   // 4 seconds
}

void Dispatcher::loop() {
  if (millisHasNowPassed(next_floor_calib_time)) {
    _radio->triggerNoiseFloorCalibrate(getInterferenceThreshold());
    _radio->setCADEnabled(getCADEnabled());
    next_floor_calib_time = futureMillis(NOISE_FLOOR_CALIB_INTERVAL);
  }
  _radio->loop();

  // check for radio 'stuck' in mode other than Rx
  bool is_recv = _radio->isInRecvMode();
  if (is_recv != prev_isrecv_mode) {
    prev_isrecv_mode = is_recv;
    if (!is_recv) {
      radio_nonrx_start = _ms->getMillis();
    }
  }
  if (!is_recv && _ms->getMillis() - radio_nonrx_start > 8000) {   // radio has not been in Rx mode for 8 seconds!
    _err_flags |= ERR_EVENT_STARTRX_TIMEOUT;
  }

  if (outbound) {  // waiting for outbound send to be completed
    if (_radio->isSendComplete()) {
      long t = _ms->getMillis() - outbound_start;
      total_air_time += t;
      //Serial.print("  airtime="); Serial.println(t);

      updateTxBudget();

      if (t > tx_budget_ms) {
        tx_budget_ms = 0;
      } else {
        tx_budget_ms -= t;
      }

#if MESHCORE_LORA_OTA
      if (outbound_is_ota) {
        if (!active_ota->recordTransmit(_ms->getMillis(), outbound_ota_category, (uint32_t)t)) {
          ++ota_accounting_failure_count;
          MESH_DEBUG_PRINTLN("%s Dispatcher::loop(): WARNING: OTA airtime accounting ring full", getLogDateTime());
        }
        outbound_is_ota = false;
      }
#endif

      if (tx_budget_ms < MIN_TX_BUDGET_RESERVE_MS) {
        float duty_cycle = 1.0f / (1.0f + getAirtimeBudgetFactor());
        unsigned long needed = MIN_TX_BUDGET_RESERVE_MS - tx_budget_ms;
        next_tx_time = futureMillis((unsigned long)(needed / duty_cycle));
      } else {
        next_tx_time = _ms->getMillis();
      }

      _radio->onSendFinished();
      logTx(outbound, 2 + outbound->getPathByteLen() + outbound->payload_len);
      if (outbound->isRouteFlood()) {
        n_sent_flood++;
      } else {
        n_sent_direct++;
      }
      releasePacket(outbound);  // return to pool
      outbound = NULL;
    } else if (millisHasNowPassed(outbound_expiry)) {
#if MESHCORE_LORA_OTA
      ++tx_timeout_count;
#endif
      MESH_DEBUG_PRINTLN("%s Dispatcher::loop(): WARNING: outbound packed send timed out!", getLogDateTime());

      _radio->onSendFinished();
      logTxFail(outbound, 2 + outbound->getPathByteLen() + outbound->payload_len);

      releasePacket(outbound);  // return to pool
      outbound = NULL;
    } else {
      return;  // can't do any more radio activity until send is complete or timed out
    }

    // going back into receive mode now...
    next_agc_reset_time = futureMillis(getAGCResetInterval());
  }

  if (getAGCResetInterval() > 0 && millisHasNowPassed(next_agc_reset_time)) {
    _radio->resetAGC();
    next_agc_reset_time = futureMillis(getAGCResetInterval());
  }

  // check inbound (delayed) queue
  {
    Packet* pkt = _mgr->getNextInbound(_ms->getMillis());
    if (pkt) {
      processRecvPacket(pkt);
    }
  }
  checkRecv();
  checkSend();
}

bool Dispatcher::tryParsePacket(Packet* pkt, const uint8_t* raw, int len) {
  int i = 0;

  pkt->header = raw[i++];
  if (pkt->getPayloadVer() > PAYLOAD_VER_1) {
    MESH_DEBUG_PRINTLN("%s Dispatcher::checkRecv(): unsupported packet version", getLogDateTime());
    return false;
  }

  if (pkt->hasTransportCodes()) {
    memcpy(&pkt->transport_codes[0], &raw[i], 2); i += 2;
    memcpy(&pkt->transport_codes[1], &raw[i], 2); i += 2;
  } else {
    pkt->transport_codes[0] = pkt->transport_codes[1] = 0;
  }

  pkt->path_len = raw[i++];
  uint8_t path_mode = pkt->path_len >> 6;  // upper 2 bits (legacy firmware: 00)
  if (path_mode == 3) {   // Reserved for future
    MESH_DEBUG_PRINTLN("%s Dispatcher::checkRecv(): unsupported path mode: 3", getLogDateTime());
    return false;
  }

  uint8_t path_byte_len = (pkt->path_len & 63) * pkt->getPathHashSize();
  if (path_byte_len > MAX_PATH_SIZE || i + path_byte_len > len) {
    MESH_DEBUG_PRINTLN("%s Dispatcher::checkRecv(): partial or corrupt packet received, len=%d", getLogDateTime(), len);
    return false;
  }

  memcpy(pkt->path, &raw[i], path_byte_len); i += path_byte_len;

  pkt->payload_len = len - i;  // payload is remainder
  if (pkt->payload_len > sizeof(pkt->payload)) {
    MESH_DEBUG_PRINTLN("%s Dispatcher::checkRecv(): packet payload too big, payload_len=%d", getLogDateTime(), (uint32_t)pkt->payload_len);
    return false;
  }

  memcpy(pkt->payload, &raw[i], pkt->payload_len);

  return true;  // success
}

__attribute__((noinline)) Packet* Dispatcher::readReceivedPacket(float& score, uint32_t& air_time) {
  Packet* pkt;
  {
    uint8_t raw[MAX_TRANS_UNIT+1];
    int len = _radio->recvRaw(raw, MAX_TRANS_UNIT);
    if (len > 0) {
      logRxRaw(_radio->getLastSNR(), _radio->getLastRSSI(), raw, len);

      pkt = _mgr->allocNew();
      if (pkt == NULL) {
        MESH_DEBUG_PRINTLN("%s Dispatcher::checkRecv(): WARNING: received data, no unused packets available!", getLogDateTime());
      } else {
        if (tryParsePacket(pkt, raw, len)) {
          // Raw ingress alloc above can't know the payload type ahead of
          // time (is_ota_bulk=false), so OTA classification/reserve
          // enforcement happens here instead, right after parsing -- this
          // single check covers raw ingress, immediate-RX, and delayed-RX
          // (the flood path below queues this same 'pkt' unchanged), so a
          // sustained burst of *incoming* OTA traffic can never push the
          // pool below the reserve out from under ordinary traffic, exactly
          // like the existing is_ota_bulk reserve does for OTA's own
          // outbound bulk allocations. See PacketManager::kOtaAllocReserve.
          if (mesh::ota::isOtaPacket(pkt) && _mgr->getFreeCount() <= PacketManager::kOtaAllocReserve) {
            MESH_DEBUG_PRINTLN("%s Dispatcher::checkRecv(): dropping inbound OTA packet, pool at/below ordinary-traffic reserve", getLogDateTime());
            _mgr->free(pkt);
            pkt = NULL;
          } else {
            pkt->_snr = _radio->getLastSNR() * 4.0f;
            score = _radio->packetScore(_radio->getLastSNR(), len);
            air_time = _radio->getEstAirtimeFor(len);
            rx_air_time += air_time;
          }
        } else {
          _mgr->free(pkt);  // put back into pool
          pkt = NULL;
        }
      }
    } else {
      pkt = NULL;
    }
  }
  return pkt;
}

void Dispatcher::checkRecv() {
  float score;
  uint32_t air_time;
  Packet* pkt = readReceivedPacket(score, air_time);
  if (pkt) {
    #if MESH_PACKET_LOGGING
    Serial.print(getLogDateTime());
    Serial.printf(": RX, len=%d (type=%d, route=%s, payload_len=%d) SNR=%d RSSI=%d score=%d time=%d", 
            pkt->getRawLength(), pkt->getPayloadType(), pkt->isRouteDirect() ? "D" : "F", pkt->payload_len,
            (int)pkt->getSNR(), (int)_radio->getLastRSSI(), (int)(score*1000), air_time);

    static uint8_t packet_hash[MAX_HASH_SIZE];
    pkt->calculatePacketHash(packet_hash);
    Serial.print(" hash=");
    mesh::Utils::printHex(Serial, packet_hash, MAX_HASH_SIZE);

    if (pkt->getPayloadType() == PAYLOAD_TYPE_PATH || pkt->getPayloadType() == PAYLOAD_TYPE_REQ
        || pkt->getPayloadType() == PAYLOAD_TYPE_RESPONSE || pkt->getPayloadType() == PAYLOAD_TYPE_TXT_MSG) {
      Serial.printf(" [%02X -> %02X]\n", (uint32_t)pkt->payload[1], (uint32_t)pkt->payload[0]);
    } else {
      Serial.printf("\n");
    }
    #endif
    logRx(pkt, pkt->getRawLength(), score);   // hook for custom logging

    if (pkt->isRouteFlood()) {
      n_recv_flood++;

      int _delay = calcRxDelay(score, air_time);
      if (_delay < 50) {
        MESH_DEBUG_PRINTLN("%s Dispatcher::checkRecv(), score delay below threshold (%d)", getLogDateTime(), _delay);
        processRecvPacket(pkt);   // is below the score delay threshold, so process immediately
      } else {
        MESH_DEBUG_PRINTLN("%s Dispatcher::checkRecv(), score delay is: %d millis", getLogDateTime(), _delay);
        if (_delay > MAX_RX_DELAY_MILLIS) {
          _delay = MAX_RX_DELAY_MILLIS;
        }
        _mgr->queueInbound(pkt, futureMillis(_delay)); // add to delayed inbound queue
      }
    } else {
      n_recv_direct++;
      processRecvPacket(pkt);
    }
  }
}

void Dispatcher::processRecvPacket(Packet* pkt) {
  DispatcherAction action = onRecvPacket(pkt);
  if (action == ACTION_RELEASE) {
    _mgr->free(pkt);
  } else if (action == ACTION_MANUAL_HOLD) {
    // sub-class is wanting to manually hold Packet instance, and call releasePacket() at appropriate time
  } else if (mesh::ota::isOtaPacket(pkt) && _mgr->getFreeCount() <= PacketManager::kOtaAllocReserve) {
    // ACTION_RETRANSMIT* for an OTA packet (relay/forward), but the pool is
    // at/below the ordinary-traffic reserve: queueing this for outbound
    // relay would hold its buffer for as long as it sits in the send queue
    // awaiting duty-cycle airtime budget (potentially many seconds), which
    // is exactly how sustained background OTA traffic starved ordinary
    // sends under physical test. Drop it instead of relaying -- OTA is
    // retry/repair-capable, ordinary traffic is not allowed to be starved.
    MESH_DEBUG_PRINTLN("%s Dispatcher::processRecvPacket(): dropping relayed OTA packet, pool at/below ordinary-traffic reserve", getLogDateTime());
    _mgr->free(pkt);
  } else {   // ACTION_RETRANSMIT*
    uint8_t priority = (action >> 24) - 1;
    uint32_t _delay = action & 0xFFFFFF;

    _mgr->queueOutbound(pkt, priority, futureMillis(_delay));
  }
}

void Dispatcher::checkSend() {
  if (_mgr->getOutboundCount(_ms->getMillis()) == 0) return;
  
  updateTxBudget();
  
  uint32_t est_airtime = _radio->getEstAirtimeFor(MAX_TRANS_UNIT);
  if (tx_budget_ms < est_airtime / MIN_TX_BUDGET_AIRTIME_DIV) {
    float duty_cycle = 1.0f / (1.0f + getAirtimeBudgetFactor());
    unsigned long needed = est_airtime / MIN_TX_BUDGET_AIRTIME_DIV - tx_budget_ms;
    next_tx_time = futureMillis((unsigned long)(needed / duty_cycle));
    return;
  }
  
  if (!millisHasNowPassed(next_tx_time)) return;
  if (_radio->isReceiving()) {
    if (cad_busy_start == 0) {
      cad_busy_start = _ms->getMillis();   // record when CAD busy state started
    }

    if (_ms->getMillis() - cad_busy_start > getCADFailMaxDuration()) {
      _err_flags |= ERR_EVENT_CAD_TIMEOUT;

      MESH_DEBUG_PRINTLN("%s Dispatcher::checkSend(): CAD busy max duration reached!", getLogDateTime());
      // channel activity has gone on too long... (Radio might be in a bad state)
      // force the pending transmit below...
    } else {
      next_tx_time = futureMillis(getCADFailRetryDelay());
      return;
    }
  }
  cad_busy_start = 0;  // reset busy state

  outbound = _mgr->getNextOutbound(_ms->getMillis(), &outbound_priority);
  if (outbound) {
    int len = 0;
    uint8_t raw[MAX_TRANS_UNIT];

    raw[len++] = outbound->header;
    if (outbound->hasTransportCodes()) {
      memcpy(&raw[len], &outbound->transport_codes[0], 2); len += 2;
      memcpy(&raw[len], &outbound->transport_codes[1], 2); len += 2;
    }
    raw[len++] = outbound->path_len;
    len += Packet::writePath(&raw[len], outbound->path, outbound->path_len);

    if (len + outbound->payload_len > MAX_TRANS_UNIT) {
      MESH_DEBUG_PRINTLN("%s Dispatcher::checkSend(): FATAL: Invalid packet queued... too long, len=%d", getLogDateTime(), len + outbound->payload_len);
      _mgr->free(outbound);
      outbound = NULL;
    } else {
      memcpy(&raw[len], outbound->payload, outbound->payload_len); len += outbound->payload_len;

      uint32_t prospective_airtime = _radio->getEstAirtimeFor(len);
      updateTxBudget();
      if (tx_budget_ms < prospective_airtime) {
        float duty_cycle = 1.0f / (1.0f + getAirtimeBudgetFactor());
        unsigned long needed = prospective_airtime - tx_budget_ms;
        unsigned long delay = duty_cycle > 0.0f ? (unsigned long)(needed / duty_cycle) : getDutyCycleWindowMs();
        Packet* held = outbound;
        // Preserve the packet's ORIGINAL queue priority on requeue instead
        // of collapsing every non-OTA packet to priority 1: that used to
        // silently discard direct/high-priority/path/trace/flood ordering
        // for any packet that happened to be budget-gated even once.
        uint8_t held_priority = held->getPayloadType() == PAYLOAD_TYPE_LORA_OTA
                                    ? mesh::ota::kOtaForwardPriority
                                    : outbound_priority;
        outbound = NULL;
        sendPacket(held, held_priority, delay);
        // Retry again soon (not after the full duty-cycle `delay`): other,
        // smaller/lower-priority-numbered packets already in the queue may
        // still be immediately budget-admissible even though this one
        // isn't yet, and they must not be starved for the whole `delay`
        // window just because this pass happened to select the larger
        // packet first.
        next_tx_time = futureMillis(delay < 1000 ? delay : 1000);
        return;
      }

#if MESHCORE_LORA_OTA
      outbound_is_ota = mesh::ota::isOtaPacket(outbound);
      if (outbound_is_ota) {
        using meshcore::ota::protocol::OtaMessageType;
        using meshcore::ota::protocol::OtaAirtimeCategory;
        outbound_ota_category = OtaAirtimeCategory::Control;
        if (outbound->payload_len >= 4 && outbound->payload[0] == 0x4F && outbound->payload[1] == 0x54) {
          uint8_t raw_type = outbound->payload[3];
          if (meshcore::ota::protocol::isKnownOtaMessageType(raw_type)) {
            outbound_ota_category = mesh::ota::otaAirtimeCategoryForMessage(static_cast<OtaMessageType>(raw_type));
          }
        }
        if (!active_ota->canTransmit(_ms->getMillis(), outbound_ota_category, prospective_airtime,
                                     true, hasQueuedNormalTraffic())) {
          Packet* held = outbound;
          outbound = NULL;
          outbound_is_ota = false;
          sendPacket(held, mesh::ota::kOtaForwardPriority, 60000);
          // Do not impose a global next_tx_time stall here: this OTA
          // packet is now shelved for 60s regardless, and normal traffic
          // taking absolute precedence (per canAdmit()) must be able to
          // send on the very next tick rather than waiting out an
          // arbitrary fixed delay behind a single deferred OTA frame.
          return;
        }
      }
#endif

      uint32_t max_airtime = prospective_airtime*3/2;
      outbound_start = _ms->getMillis();
      bool success = _radio->startSendRaw(raw, len);
      if (!success) {
        MESH_DEBUG_PRINTLN("%s Dispatcher::loop(): ERROR: send start failed!", getLogDateTime());

        logTxFail(outbound, outbound->getRawLength());
  
        releasePacket(outbound);  // return to pool
        outbound = NULL;
        return;
      }
      outbound_expiry = futureMillis(max_airtime);

    #if MESH_PACKET_LOGGING
      Serial.print(getLogDateTime());
      Serial.printf(": TX, len=%d (type=%d, route=%s, payload_len=%d)", 
            len, outbound->getPayloadType(), outbound->isRouteDirect() ? "D" : "F", outbound->payload_len);
      if (outbound->getPayloadType() == PAYLOAD_TYPE_PATH || outbound->getPayloadType() == PAYLOAD_TYPE_REQ
        || outbound->getPayloadType() == PAYLOAD_TYPE_RESPONSE || outbound->getPayloadType() == PAYLOAD_TYPE_TXT_MSG) {
        Serial.printf(" [%02X -> %02X]\n", (uint32_t)outbound->payload[1], (uint32_t)outbound->payload[0]);
      } else {
        Serial.printf("\n");
      }
    #endif
    }
  }
}

Packet* Dispatcher::obtainNewPacket(bool is_ota_bulk) {
  auto pkt = _mgr->allocNew(is_ota_bulk);  // TODO: zero out all fields
  if (pkt == NULL) {
    _err_flags |= ERR_EVENT_FULL;
  } else {
    pkt->payload_len = pkt->path_len = 0;
    pkt->_snr = 0;
  }
  return pkt;
}

void Dispatcher::releasePacket(Packet* packet) {
  _mgr->free(packet);
}

bool Dispatcher::sendPacket(Packet* packet, uint8_t priority, uint32_t delay_millis) {
  if (!Packet::isValidPathLen(packet->path_len) || packet->payload_len > MAX_PACKET_PAYLOAD) {
    MESH_DEBUG_PRINTLN("%s Dispatcher::sendPacket(): ERROR: invalid packet... path_len=%d, payload_len=%d", getLogDateTime(), (uint32_t) packet->path_len, (uint32_t) packet->payload_len);
    _mgr->free(packet);
    return false;
  } else {
    return _mgr->queueOutbound(packet, priority, futureMillis(delay_millis));
  }
}

#if MESHCORE_LORA_OTA
bool Dispatcher::hasQueuedNormalTraffic() {
  // getOutboundCount(now) only tells us *some* entry (of any kind) is
  // ready now; it does NOT mean the specific entries this loop finds
  // below are ready. The previous implementation scanned every queued
  // entry unconditionally, so a normal packet scheduled arbitrarily far
  // in the future (e.g. a delayed advert) would still count as "queued
  // normal traffic" and block OTA relay/repair transmission even though
  // no normal packet was actually ready to send. Skip any entry whose
  // scheduled_for has not arrived yet.
  if (_mgr->getOutboundCount(_ms->getMillis()) == 0) return false;
  const uint32_t now = _ms->getMillis();
  const int total = _mgr->getOutboundTotal();
  for (int i = 0; i < total; ++i) {
    if ((int32_t)(_mgr->getOutboundScheduledForByIdx(i) - now) > 0) continue;  // not ready yet
    Packet* packet = _mgr->getOutboundByIdx(i);
    if (packet != nullptr && !mesh::ota::isOtaPacket(packet)) return true;
  }
  return false;
}

bool Dispatcher::hasQueuedOtaTraffic() {
  if (_mgr->getOutboundCount(_ms->getMillis()) == 0) return false;
  const uint32_t now = _ms->getMillis();
  const int total = _mgr->getOutboundTotal();
  for (int i = 0; i < total; ++i) {
    if ((int32_t)(_mgr->getOutboundScheduledForByIdx(i) - now) > 0) continue;  // not ready yet
    Packet* packet = _mgr->getOutboundByIdx(i);
    if (packet != nullptr && mesh::ota::isOtaPacket(packet)) return true;
  }
  return false;
}
#endif

// Utility function -- handles the case where millis() wraps around back to zero
//   2's complement arithmetic will handle any unsigned subtraction up to HALF the word size (32-bits in this case)
bool Dispatcher::millisHasNowPassed(unsigned long timestamp) const {
  return (long)(_ms->getMillis() - timestamp) > 0;
}

unsigned long Dispatcher::futureMillis(int millis_from_now) const {
  return _ms->getMillis() + millis_from_now;
}

}
