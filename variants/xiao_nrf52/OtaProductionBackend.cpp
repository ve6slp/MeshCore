#include <Arduino.h>
#if MESHCORE_LORA_OTA && defined(XIAO_NRF52)
#define MESHCORE_V4_NRF_TARGET 0x584E3430u
#define MESHCORE_V4_NRF_ROLE_ID XIAO_OTA_COMPILED_ROLE_ID
#include <helpers/ota/OtaBoardNrf52Backend.h>
#endif
