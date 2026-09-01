#include "remoteusb.h"

#include <string.h>
#include <stdio.h>

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "check failed: %s\\n", #condition); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    static const uint8_t capability[] = {
        9, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0,
        0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0, 11, 1, 0, 0, 0,
        2, 0, 0, 0, 'm', 'o', 'o', 'n', 'l', 'i', 'g', 'h', 't', '-', '1',
        2, 1, 0, 0, 0x81, 3, 64, 0, 1, 0
    };
    rusb_session_config config;
    rusb_session *session = NULL;
    rusb_event event;
    uint8_t hello[84];

    memset(&config, 0, sizeof(config));
    config.size = sizeof(config);
    config.version = RUSB_CORE_ABI_VERSION;
    config.role = RUSB_ROLE_EXPORTER;
    memcpy(config.client_uuid, "test-client-uuid", 16);
    config.stream_generation = 2;
    config.session_token = 3;
    config.attachment_token = 7;
    config.lease_token = 9;
    memset(config.capability_nonce, 6, sizeof(config.capability_nonce));
    config.max_pdu = 4096;
    config.max_inflight = 4;
    config.max_reassembly_size = 4096;
    config.max_fragments = 4;
    config.max_transfer_size = 4096 - 48;

    CHECK(rusb_core_abi_version() == RUSB_CORE_ABI_VERSION);
    CHECK(rusb_core_protocol_version() == RUSB_CORE_PROTOCOL_VERSION);
    CHECK(rusb_session_create(&config, &session) == RUSB_STATUS_OK);
    CHECK(session != NULL);
    CHECK(rusb_session_start(session) == RUSB_STATUS_OK);

    memset(&event, 0, sizeof(event));
    CHECK(rusb_session_next_event(session, &event) == RUSB_STATUS_OK);
    CHECK(event.kind == RUSB_EVENT_OUTPUT_HELLO);
    CHECK(event.data_length == sizeof(hello));
    memcpy(hello, event.data, sizeof(hello));

    CHECK(rusb_session_accept_hello(session, hello, sizeof(hello)) == RUSB_STATUS_OK);
    CHECK(rusb_session_send_capability(session, capability, sizeof(capability)) ==
          RUSB_STATUS_OK);
    CHECK(rusb_session_next_event(session, &event) == RUSB_STATUS_OK);
    CHECK(event.kind == RUSB_EVENT_OUTPUT_FRAME);
    CHECK(event.reservation_id == 0);
    CHECK(event.data_length > sizeof(capability));

    CHECK(rusb_session_destroy(session) == RUSB_STATUS_OK);
    return 0;
}
