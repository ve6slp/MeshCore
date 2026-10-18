#include <Arduino.h>
#if MESHCORE_LORA_OTA && defined(XIAO_NRF52)
#define MESHCORE_V4_NRF_TARGET 0x584E3430u
#include <helpers/ota/OtaBoardNrf52Backend.h>
#endif
