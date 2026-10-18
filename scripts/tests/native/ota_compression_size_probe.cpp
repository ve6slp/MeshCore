#include <helpers/ota/OtaLzma.h>
#include <helpers/ota/OtaV4Receiver.h>
extern "C" {
mesh::ota::OtaLzma ota_decoder_workspace;
uint8_t ota_decoder_input[mesh::ota::v4::kChunkBytes],ota_decoder_output[mesh::ota::v4::kChunkBytes];
uint8_t ota_receiver_size[sizeof(mesh::ota::v4::Receiver)];
uint8_t ota_compression_state_size[sizeof(mesh::ota::OtaLzma) + 2 * mesh::ota::v4::kChunkBytes];
int ota_decode_probe(size_t stored,size_t raw) {
  auto result=ota_decoder_workspace.begin(ota_decoder_input,stored,ota_decoder_output,raw);
  while(result==mesh::ota::OtaLzma::Result::Pending) result=ota_decoder_workspace.step();
  return static_cast<int>(result);
}
}
