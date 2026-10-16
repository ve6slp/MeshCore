#include <helpers/ota/OtaLzma.h>
#include <helpers/ota/OtaLeanReceiver.h>
extern "C" {
mesh::ota::OtaLzma ota_decoder_workspace;
uint8_t ota_decoder_input[8064],ota_decoder_output[8064];
uint8_t ota_receiver_size[sizeof(mesh::ota::OtaLeanReceiver)];
uint8_t ota_compression_state_size[sizeof(mesh::ota::OtaLeanReceiver::CompressionWorkspace)];
int ota_decode_probe(size_t stored,size_t raw) {
  auto result=ota_decoder_workspace.begin(ota_decoder_input,stored,ota_decoder_output,raw);
  while(result==mesh::ota::OtaLzma::Result::Pending) result=ota_decoder_workspace.step();
  return static_cast<int>(result);
}
}
