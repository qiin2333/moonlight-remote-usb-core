# Moonlight Remote USB Core

`moonlight-remote-usb-core` is the platform-neutral protocol engine for raw USB
forwarding between Moonlight and Sunshine. It owns protocol parsing, validation,
flow control, fragmentation, and request lifecycle. It does not own USB devices,
sockets, TLS, threads, or user authorization.

The stable integration surface is the C ABI in `include/remoteusb.h`. Rust users
may use the typed API directly. Both APIs implement the normative contract in
`contract/protocol-v1.md`; `contract/vectors-v1.json` is the cross-language
compatibility oracle.

## Boundaries

Inside the core:

- RUSB HELLO and frame codecs
- capability/open/close state validation
- USB/IP control and URB PDU codecs
- bounded fragmentation and reassembly
- flow control and SUBMIT/UNLINK lifecycle
- a caller-driven session/event engine

Outside the core:

- Qt, JNI, libusb, usbfs, `usbip-win2`
- sockets, TLS, pairing, discovery, and NAT traversal
- platform USB permissions and device ownership
- UI policy and persistent device identity

The core has no runtime crate dependencies and does not create worker threads.

