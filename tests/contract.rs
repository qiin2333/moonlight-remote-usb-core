use moonlight_remote_usb_core::broker::Hello;
use moonlight_remote_usb_core::pdu::{Direction, Request, SubmitRequest, UnlinkRequest};
use moonlight_remote_usb_core::usbip::ControlRequest;
use moonlight_remote_usb_core::wire::{self, Capability, Endpoint, FrameHeader, MessageType, Open};
use std::fmt::Write;

const VECTORS: &str = include_str!("../contract/vectors-v1.json");

fn vector(name: &str) -> String {
    let marker = format!("\"{name}\": \"");
    let start = VECTORS.find(&marker).expect("vector name") + marker.len();
    let end = VECTORS[start..].find('"').expect("vector terminator") + start;
    VECTORS[start..end].to_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        },
    )
}

fn hello() -> Hello {
    Hello {
        client_uuid: *b"test-client-uuid",
        stream_generation: 2,
        session_token: 3,
        attachment_token: 7,
        lease_token: 9,
        capability_nonce: [6; 16],
        max_pdu: 4096,
        max_inflight: 4,
        isochronous: false,
    }
}

fn capability() -> Capability {
    Capability {
        lease_token: 9,
        attachment_token: 7,
        vendor_id: 0x1234,
        product_id: 0x5678,
        device_bcd: 0x0100,
        device_class: 0,
        device_subclass: 0,
        device_protocol: 0,
        bus_id: b"moonlight-1".to_vec(),
        raw_descriptors: vec![18, 1, 0, 2],
        endpoints: vec![Endpoint {
            interface_number: 0,
            alternate_setting: 0,
            address: 0x81,
            attributes: 3,
            max_packet_size: 64,
            interval: 1,
        }],
    }
}

#[test]
fn normative_v1_vectors_match_codecs() {
    assert_eq!(hex(&hello().encode().unwrap()), vector("hello"));

    let capability = capability().encode().unwrap();
    assert_eq!(hex(&capability), vector("capability_payload"));
    assert_eq!(
        hex(&wire::encode_frame(
            FrameHeader {
                message_type: MessageType::Capability,
                flags: 0,
                payload_length: u32::try_from(capability.len()).unwrap(),
                session_token: 3,
                sequence: 1,
            },
            &capability,
        )
        .unwrap()),
        vector("capability_frame")
    );

    let open = Open {
        lease_token: 9,
        attachment_token: 7,
    }
    .encode()
    .unwrap();
    assert_eq!(hex(&open), vector("open_payload"));
    assert_eq!(
        hex(&wire::encode_frame(
            FrameHeader {
                message_type: MessageType::Open,
                flags: 0,
                payload_length: u32::try_from(open.len()).unwrap(),
                session_token: 3,
                sequence: 2,
            },
            &open,
        )
        .unwrap()),
        vector("open_frame")
    );

    let submit = Request::Submit(SubmitRequest {
        seqnum: 17,
        device_id: 0x0001_0001,
        direction: Direction::In,
        endpoint: 1,
        transfer_flags: 0,
        transfer_buffer_length: 8,
        start_frame: 0,
        interval: 0,
        setup: [0; 8],
        data: Vec::new(),
    })
    .encode()
    .unwrap();
    assert_eq!(hex(&submit), vector("usbip_submit"));

    let unlink = Request::Unlink(UnlinkRequest {
        seqnum: 18,
        device_id: 0x0001_0001,
        direction: Direction::In,
        endpoint: 1,
        target_seqnum: 17,
    })
    .encode()
    .unwrap();
    assert_eq!(hex(&unlink), vector("usbip_unlink"));

    let import = ControlRequest::Import {
        bus_id: "moonlight-1".into(),
    }
    .encode()
    .unwrap();
    assert_eq!(hex(&import), vector("usbip_import"));
}

#[test]
fn vector_file_is_valid_json_shape_without_runtime_json_dependency() {
    assert!(VECTORS.trim_start().starts_with('{'));
    assert!(VECTORS.trim_end().ends_with('}'));
    for name in [
        "hello",
        "capability_payload",
        "capability_frame",
        "open_payload",
        "open_frame",
        "usbip_submit",
        "usbip_fragment",
        "usbip_unlink",
        "usbip_import",
    ] {
        let value = vector(name);
        assert!(!value.is_empty());
        assert_eq!(value.len() % 2, 0);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
