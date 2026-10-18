#include <Arduino.h>
#if defined(MESHCORE_LORA_OTA) && MESHCORE_LORA_OTA
#define MESHCORE_V4_NRF_TARGET 0x53435031u
#define MESHCORE_V4_NRF_ROLE_ID SENSECAP_OTA_COMPILED_ROLE_ID
#include <helpers/ota/OtaBoardNrf52Backend.h>
#endif
