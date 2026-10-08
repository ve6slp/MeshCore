#pragma once

#include <Dispatcher.h>
#include <deque>
#include <memory>
#include <vector>

// This downstream-style implementation overrides only the upstream dev API.
class LegacyPacketManager : public mesh::PacketManager {
  struct Entry {
    mesh::Packet* packet;
    uint8_t priority;
    uint32_t scheduled_for;
  };
  std::vector<std::unique_ptr<mesh::Packet>> pool;
  std::deque<mesh::Packet*> unused;
  std::vector<Entry> outbound;
  std::vector<Entry> inbound;

  static mesh::Packet* pop(std::vector<Entry>& queue, uint32_t now) {
    auto best = queue.end();
    for (auto i = queue.begin(); i != queue.end(); ++i) {
      if (static_cast<int32_t>(i->scheduled_for - now) > 0) continue;
      if (best == queue.end() || i->priority < best->priority) best = i;
    }
    if (best == queue.end()) return nullptr;
    auto* packet = best->packet;
    queue.erase(best);
    return packet;
  }

public:
  int submissions = 0;
  int releases = 0;
  bool drop_submission = false;
  uint8_t last_priority = 0;
  uint32_t last_schedule = 0;

  explicit LegacyPacketManager(int count = 8) {
    for (int i = 0; i < count; ++i) {
      pool.emplace_back(new mesh::Packet);
      unused.push_back(pool.back().get());
    }
  }
  mesh::Packet* allocNew() override {
    if (unused.empty()) return nullptr;
    auto* packet = unused.front();
    unused.pop_front();
    return packet;
  }
  void free(mesh::Packet* packet) override {
    if (packet != nullptr) {
      ++releases;
      unused.push_back(packet);
    }
  }
  void queueOutbound(mesh::Packet* packet, uint8_t priority, uint32_t scheduled_for) override {
    ++submissions;
    last_priority = priority;
    last_schedule = scheduled_for;
    if (drop_submission) free(packet);
    else outbound.push_back({packet, priority, scheduled_for});
  }
  mesh::Packet* getNextOutbound(uint32_t now) override { return pop(outbound, now); }
  int getOutboundCount(uint32_t now) const override {
    int count = 0;
    for (const auto& entry : outbound) {
      if (static_cast<int32_t>(entry.scheduled_for - now) <= 0) ++count;
    }
    return count;
  }
  int getOutboundTotal() const override { return outbound.size(); }
  int getFreeCount() const override { return unused.size(); }
  mesh::Packet* getOutboundByIdx(int i) override {
    return i >= 0 && i < static_cast<int>(outbound.size()) ? outbound[i].packet : nullptr;
  }
  mesh::Packet* removeOutboundByIdx(int i) override {
    auto* packet = getOutboundByIdx(i);
    if (packet != nullptr) outbound.erase(outbound.begin() + i);
    return packet;
  }
  void queueInbound(mesh::Packet* packet, uint32_t scheduled_for) override {
    inbound.push_back({packet, 0, scheduled_for});
  }
  mesh::Packet* getNextInbound(uint32_t now) override { return pop(inbound, now); }
};
