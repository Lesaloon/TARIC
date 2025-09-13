#include "taric_client.h"
#include <string.h>

// Minimal stubs for now; implement later.
int taric_build_signed_entry(const taric_client_cfg_t* cfg,
                             const uint8_t* payload, size_t payload_len,
                             const char* algo, const char* key_id,
                             uint8_t* out_buf, size_t* out_len) {
  (void)cfg; (void)payload; (void)payload_len; (void)algo; (void)key_id;
  const char* placeholder = "{\"todo\":\"build signed entry\"}\n";
  size_t n = strlen(placeholder);
  if (*out_len < n) return -1;
  memcpy(out_buf, placeholder, n);
  *out_len = n;
  return 0;
}

int taric_verify_ack(const taric_client_cfg_t* cfg,
                     const uint8_t* ack_bytes, size_t ack_len) {
  (void)cfg; (void)ack_bytes; (void)ack_len;
  // TODO: parse and verify signature with cfg->verify_server_ack
  return 0;
}
