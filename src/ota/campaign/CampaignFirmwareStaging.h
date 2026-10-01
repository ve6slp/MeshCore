#pragma once

#include <helpers/ota/OtaFirmwareBackend.h>
#include "CampaignPorts.h"

namespace meshcore {
namespace ota {
namespace campaign {

// Campaign ports delegate to the same sink used by the firmware runtime,
// including its optional durable bootloader handoff.
class CampaignFirmwareStagingSink : public runtime::IOtaStagingSink,
                                    public IOtaStagingResumePort {
public:
  explicit CampaignFirmwareStagingSink(::ota::platform::FlashRegion& region)
      : sink_(region) {}

  CampaignFirmwareStagingSink(::ota::platform::FlashRegion& region,
                              ::ota::platform::FlashRegion* commandRegion,
                              ::mesh::ota::IOtaInstallCommandProviderV2* provider)
      : sink_(region, commandRegion, provider) {}

  Result beginSession(const protocol::OtaDescriptor& descriptor) override {
    return sink_.beginSession(descriptor);
  }

  bool resumeSession(const protocol::OtaDescriptor& descriptor) override {
    return sink_.resumeSession(descriptor) == Result::Ok;
  }

  Result writeChunk(uint64_t offset, const uint8_t* data, size_t len) override {
    return sink_.writeChunk(offset, data, len);
  }

  Result commit() override { return sink_.commit(); }
  void abort() override { sink_.abort(); }

  void onVerifiedWireDescriptor(const uint8_t* descriptor, size_t descriptorLen,
                                const uint8_t* signature, size_t signatureLen) override {
    sink_.onVerifiedWireDescriptor(descriptor, descriptorLen, signature, signatureLen);
  }

  void onAuthorizedSession(const runtime::OtaSessionId& session,
                            const uint8_t controller[32]) override {
    sink_.onAuthorizedSession(session, controller);
  }

  bool isActive() const { return sink_.isActive(); }
  bool isCommitted() const { return sink_.isCommitted(); }
  bool haveVerifiedWireDescriptor() const { return sink_.haveVerifiedWireDescriptor(); }
  bool haveAuthorizedSession() const { return sink_.haveAuthorizedSession(); }
  const uint8_t* verifiedWireDescriptor() const { return sink_.verifiedWireDescriptor(); }
  const uint8_t* authorizedController() const { return sink_.authorizedController(); }

private:
  ::mesh::ota::OtaFirmwareStorageSink sink_;
};

} // namespace campaign
} // namespace ota
} // namespace meshcore
