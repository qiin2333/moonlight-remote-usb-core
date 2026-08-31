#ifndef MOONLIGHT_REMOTE_USB_CORE_H
#define MOONLIGHT_REMOTE_USB_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RUSB_CORE_ABI_VERSION 1u
#define RUSB_CORE_PROTOCOL_VERSION 1u

typedef struct rusb_session rusb_session;

typedef enum rusb_status {
    RUSB_STATUS_OK = 0,
    RUSB_STATUS_INVALID_ARGUMENT = 1,
    RUSB_STATUS_BUFFER_TOO_SMALL = 2,
    RUSB_STATUS_VERSION_MISMATCH = 3,
    RUSB_STATUS_BAD_MAGIC = 4,
    RUSB_STATUS_MALFORMED = 5,
    RUSB_STATUS_TOKEN_MISMATCH = 6,
    RUSB_STATUS_SEQUENCE_ERROR = 7,
    RUSB_STATUS_INVALID_STATE = 8,
    RUSB_STATUS_LIMIT_EXCEEDED = 9,
    RUSB_STATUS_WINDOW_EXHAUSTED = 10,
    RUSB_STATUS_DUPLICATE = 11,
    RUSB_STATUS_NOT_FOUND = 12,
    RUSB_STATUS_BUSY = 13,
    RUSB_STATUS_UNSUPPORTED = 14,
    RUSB_STATUS_NO_MEMORY = 15,
    RUSB_STATUS_INTERNAL = 255
} rusb_status;

typedef enum rusb_role {
    RUSB_ROLE_EXPORTER = 1,
    RUSB_ROLE_IMPORTER = 2
} rusb_role;

typedef enum rusb_event_kind {
    RUSB_EVENT_NONE = 0,
    RUSB_EVENT_OUTPUT_HELLO = 1,
    RUSB_EVENT_OUTPUT_FRAME = 2,
    RUSB_EVENT_CAPABILITY = 3,
    RUSB_EVENT_OPEN = 4,
    RUSB_EVENT_OPENED = 5,
    RUSB_EVENT_OPEN_REJECTED = 6,
    RUSB_EVENT_SUBMIT = 7,
    RUSB_EVENT_CANCEL = 8,
    RUSB_EVENT_OPAQUE_PDU = 9,
    RUSB_EVENT_CLOSED = 10
} rusb_event_kind;

typedef struct rusb_session_config {
    uint32_t size;
    uint32_t version;
    uint32_t role;
    uint32_t reserved;
    uint8_t client_uuid[16];
    uint64_t stream_generation;
    uint64_t session_token;
    uint64_t attachment_token;
    uint64_t lease_token;
    uint8_t capability_nonce[16];
    uint32_t max_pdu;
    uint32_t max_inflight;
    uint8_t isochronous;
    uint8_t reserved_tail[7];
    uint64_t tx_window_bytes;
    uint32_t tx_window_pdus;
    uint32_t reserved_tx;
    uint64_t rx_window_bytes;
    uint32_t rx_window_pdus;
    uint32_t reserved_rx;
    uint32_t max_reassembly_size;
    uint32_t max_fragments;
    uint32_t max_transfer_size;
    uint32_t reserved_limits;
} rusb_session_config;

typedef struct rusb_completion {
    uint32_t size;
    uint32_t version;
    int32_t status;
    uint32_t actual_length;
    int32_t start_frame;
    int32_t error_count;
    const uint8_t *data;
    size_t data_length;
} rusb_completion;

/* Event pointers are borrowed until the next call on the same session. The
 * caller must copy data before advancing the owner loop. reservation_id is
 * zero for control output; non-zero output must be acknowledged once after
 * the complete frame sequence has drained. For fragmented OUTPUT_FRAME
 * events, flags contains RUSB's MORE bit (1) so the final frame is explicit. */
typedef struct rusb_event {
    uint32_t size;
    uint32_t version;
    uint32_t kind;
    uint32_t flags;
    uint64_t reservation_id;
    uint64_t request_token;
    uint64_t pdu_id;
    uint32_t sequence;
    uint32_t device_id;
    uint32_t direction;
    uint32_t endpoint;
    uint32_t transfer_flags;
    uint32_t transfer_buffer_length;
    int32_t start_frame;
    int32_t interval;
    int32_t status;
    uint8_t setup[8];
    const uint8_t *data;
    size_t data_length;
} rusb_event;

uint32_t rusb_core_abi_version(void);
uint32_t rusb_core_protocol_version(void);

uint32_t rusb_session_create(const rusb_session_config *config,
                             rusb_session **out_session);
uint32_t rusb_session_destroy(rusb_session *session);
uint32_t rusb_session_start(rusb_session *session);
uint32_t rusb_session_accept_hello(rusb_session *session,
                                   const uint8_t *wire, size_t wire_size);
uint32_t rusb_session_accept_frame(rusb_session *session,
                                   const uint8_t *wire, size_t wire_size);

/* capability_payload is the normative v1 CAPABILITY payload, not a native
 * struct. This keeps the ABI small and makes the shared vectors directly
 * usable from C, C++, Java/Kotlin JNI, and Swift. */
uint32_t rusb_session_send_capability(rusb_session *session,
                                      const uint8_t *capability_payload,
                                      size_t payload_size);
uint32_t rusb_session_send_open(rusb_session *session);
uint32_t rusb_session_send_open_result(rusb_session *session, uint32_t status);
uint32_t rusb_session_send_pdu(rusb_session *session, uint64_t pdu_id,
                               const uint8_t *pdu, size_t pdu_size);
uint32_t rusb_session_ack_output(rusb_session *session,
                                 uint64_t reservation_id);
uint32_t rusb_session_complete(rusb_session *session, uint64_t request_token,
                               const rusb_completion *completion);
uint32_t rusb_session_complete_cancel(rusb_session *session,
                                      uint64_t request_token, int32_t status);
uint32_t rusb_session_close(rusb_session *session);
uint32_t rusb_session_next_event(rusb_session *session, rusb_event *out_event);
uint32_t rusb_session_state(const rusb_session *session);
size_t rusb_session_inflight(const rusb_session *session);

#ifdef __cplusplus
}
#endif

#endif /* MOONLIGHT_REMOTE_USB_CORE_H */
