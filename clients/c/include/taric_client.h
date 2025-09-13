#ifndef TARIC_CLIENT_H
#define TARIC_CLIENT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const char* device_id;
  int (*sign)(const uint8_t* msg, size_t len, uint8_t* sig_out, size_t* sig_len);
  int (*verify_server_ack)(const uint8_t* msg, size_t len,
                           const uint8_t* sig, size_t sig_len,
                           const char* signer_id);
  uint64_t (*now_unix_ms)(void);
  int (*rng)(uint8_t* out, size_t len);
} taric_client_cfg_t;

int taric_build_signed_entry(const taric_client_cfg_t* cfg,
                             const uint8_t* payload, size_t payload_len,
                             const char* algo, const char* key_id,
                             uint8_t* out_buf, size_t* out_len);

int taric_verify_ack(const taric_client_cfg_t* cfg,
                     const uint8_t* ack_bytes, size_t ack_len);

#ifdef __cplusplus
}
#endif

#endif // TARIC_CLIENT_H
