#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct quinn_ffi_endpoint_t quinn_ffi_endpoint_t;
typedef struct quinn_ffi_connection_t quinn_ffi_connection_t;
typedef struct quinn_ffi_bidi_stream_t quinn_ffi_bidi_stream_t;

enum {
    QUINN_FFI_BACKEND_SYSCALL = 0,
    QUINN_FFI_BACKEND_IOURING = 1,
};

typedef struct quinn_ffi_endpoint_config_t {
    bool is_server;
    const uint8_t *address;
    uint16_t port;
    const char *cert_path;
    const char *key_path;
    const char *chain_path;
    uint32_t backend;
    bool tls_verify_peer;
    bool aggressive_congestion;
    uint32_t initial_cwnd_packets;
    uint32_t ack_frequency_packets;
} quinn_ffi_endpoint_config_t;

quinn_ffi_endpoint_t *quinn_ffi_endpoint_new(const quinn_ffi_endpoint_config_t *config);

void quinn_ffi_endpoint_free(quinn_ffi_endpoint_t *endpoint);

uintptr_t quinn_ffi_endpoint_send_buffer_size(const quinn_ffi_endpoint_t *endpoint);

uintptr_t quinn_ffi_endpoint_recv_buffer_size(const quinn_ffi_endpoint_t *endpoint);

int quinn_ffi_client_connect(
    quinn_ffi_endpoint_t *endpoint,
    const uint8_t address[16],
    uint16_t port,
    quinn_ffi_connection_t **connection);

int quinn_ffi_server_accept(
    quinn_ffi_endpoint_t *endpoint,
    quinn_ffi_connection_t **connection);

void quinn_ffi_connection_free(quinn_ffi_connection_t *connection);

void quinn_ffi_connection_close(quinn_ffi_connection_t *connection);

int quinn_ffi_connection_closed(quinn_ffi_connection_t *connection);

int quinn_ffi_connection_open_bi(
    quinn_ffi_connection_t *connection,
    quinn_ffi_bidi_stream_t **stream);

int quinn_ffi_connection_accept_bi(
    quinn_ffi_connection_t *connection,
    quinn_ffi_bidi_stream_t **stream);

void quinn_ffi_bidi_stream_free(quinn_ffi_bidi_stream_t *stream);

int quinn_ffi_stream_send_all(
    quinn_ffi_bidi_stream_t *stream,
    const uint8_t *data,
    uintptr_t len);

int quinn_ffi_stream_recv_exact(
    quinn_ffi_bidi_stream_t *stream,
    uint8_t *data,
    uintptr_t len);

int quinn_ffi_stream_recv_finish(quinn_ffi_bidi_stream_t *stream);

int quinn_ffi_stream_finish(quinn_ffi_bidi_stream_t *stream);

int quinn_ffi_stream_drain_for(quinn_ffi_bidi_stream_t *stream, uint32_t timeout_ms);

const char *quinn_ffi_last_error(void);

#ifdef __cplusplus
}
#endif
