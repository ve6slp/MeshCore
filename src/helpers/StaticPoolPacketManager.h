#pragma once

#include <Dispatcher.h>

class PacketQueue {
  mesh::Packet** _table;
  uint8_t* _pri_table;
  uint32_t* _schedule_table;
  int _size, _num;

public:
  PacketQueue(int max_entries);
  mesh::Packet* get(uint32_t now, uint8_t* out_priority = nullptr);
  bool add(mesh::Packet* packet, uint8_t priority, uint32_t scheduled_for);
  int count() const { return _num; }
  int countBefore(uint32_t now) const;
  mesh::Packet* itemAt(int i) const {
    if (i < 0 || i >= _num) return NULL;
    return _table[i];
  }
  uint8_t priorityAt(int i) const { return i >= 0 && i < _num ? _pri_table[i] : 0; }
  uint32_t scheduledForAt(int i) const { return i >= 0 && i < _num ? _schedule_table[i] : 0; }
  mesh::Packet* removeByIdx(int i);
};

class StaticPoolPacketManager : public mesh::PacketManager {
  PacketQueue unused, send_queue, rx_queue;

public:
  StaticPoolPacketManager(int pool_size);

  // Dispatcher also enforces this reserve after ingress parsing and on relay.
  static constexpr int kOtaAllocReserve = mesh::PacketManager::kOtaAllocReserve;

  mesh::Packet* allocNew() override;
  void free(mesh::Packet* packet) override;
  void queueOutbound(mesh::Packet* packet, uint8_t priority, uint32_t scheduled_for) override;
  mesh::Packet* getNextOutbound(uint32_t now) override;
  int getOutboundCount(uint32_t now) const override;
  int getOutboundTotal() const override;
  int getFreeCount() const override;
  mesh::Packet* getOutboundByIdx(int i) override;
  mesh::Packet* removeOutboundByIdx(int i) override;
  void queueInbound(mesh::Packet* packet, uint32_t scheduled_for) override;
  mesh::Packet* getNextInbound(uint32_t now) override;

  bool supportsOtaQueue() const override { return true; }
  mesh::Packet* allocOtaPacket() override;
  bool tryQueueOutbound(mesh::Packet* packet, uint8_t priority, uint32_t scheduled_for) override;
  mesh::Packet* getNextOutboundWithPriority(uint32_t now, uint8_t* out_priority) override;
  bool getOutboundScheduleByIdx(int i, uint32_t& scheduled_for) const override;
};
