# Remote USB Protocol v1

Status: **Normative**

Protocol identifier: `RUSB`

Protocol version: `1`

This document defines the authenticated Remote USB byte protocol shared by
Moonlight exporters and Sunshine importers. The words MUST, MUST NOT, SHOULD,
SHOULD NOT, and MAY are interpreted as described by RFC 2119.

## 1. Scope and trust boundary

RUSB runs inside an already authenticated, confidential, integrity-protected
stream bound to a paired Moonlight/Sunshine identity. RUSB v1 provides no
encryption and MUST NOT be exposed directly on a LAN or the public Internet.

One RUSB stream carries one USB attachment lease. A peer MUST serialize frames
in stream order. Implementations MUST bound all allocations and request queues.

## 2. Integer and string encoding

RUSB integers are unsigned little-endian unless explicitly stated otherwise.
USB/IP control messages and URB PDUs retain the USB/IP network-byte-order
(big-endian) encoding. Fixed reserved bytes MUST be zero when sent and MUST be
rejected when non-zero. Text fields are byte strings, not locale strings.

## 3. Limits

| Name | v1 value |
| --- | ---: |
| HELLO size | 84 bytes |
| Frame header size | 32 bytes |
| Maximum frame payload | 131072 bytes |
| Maximum complete USB/IP PDU | 1048576 bytes |
| Maximum PDU fragment count | 4096 |
| Maximum concurrent requests | 4096 |
| Maximum capability bus-id | 31 bytes |
| Maximum raw descriptor blob | 65536 bytes |
| Maximum endpoint records | 256 |

Peers MAY advertise lower `max_pdu` and `max_inflight` values. Negotiated values
are the minima. A peer MUST reject a value larger than the authenticated local
offer instead of silently expanding its limits.

## 4. HELLO

Both peers send exactly one HELLO before framed traffic. Receiving the same
capability nonce twice on one session is a fatal replay error.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `52 55 53 42` (`RUSB`) |
| 4 | 2 | protocol version, `1` |
| 6 | 2 | HELLO size, `84` |
| 8 | 16 | client UUID bytes |
| 24 | 8 | stream generation |
| 32 | 8 | session token |
| 40 | 8 | attachment token |
| 48 | 8 | lease token |
| 56 | 16 | single-use capability nonce |
| 72 | 4 | maximum complete USB/IP PDU |
| 76 | 4 | maximum concurrent requests |
| 80 | 1 | isochronous support (`0` in v1) |
| 81 | 3 | reserved, zero |

UUID and nonce MUST not be all-zero. Generation and all tokens MUST be non-zero.
`max_pdu` MUST be in `[49, 1048576]`; `max_inflight` MUST be in `[1, 4096]`.
Isochronous support MUST be zero in v1.

## 5. Frame header

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `RUSB` |
| 4 | 1 | protocol version, `1` |
| 5 | 1 | message type |
| 6 | 2 | header size, `32` |
| 8 | 4 | flags |
| 12 | 4 | payload length |
| 16 | 8 | session token |
| 24 | 8 | monotonically increasing sequence |

Sequences start at one, are contiguous, and MUST NOT be zero or
`0xffffffffffffffff`. A gap, replay, or wrap is fatal. The payload MUST follow
the header immediately and match `payload length` exactly.

Message types are: `1 CAPABILITY`, `2 OPEN`, `3 OPEN_OK`, `4 OPEN_REJECT`,
`5 USBIP_DATA`, and `6 CLOSE`. The only flag is `MORE = 0x00000001`, legal only
on `USBIP_DATA`. Unknown types or flag bits MUST be rejected.

## 6. Control payloads

### 6.1 CAPABILITY

The fixed 34-byte prefix is followed by bus-id bytes, raw descriptors, then
eight-byte endpoint records.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | lease token |
| 8 | 8 | attachment token |
| 16 | 2 | vendor id |
| 18 | 2 | product id |
| 20 | 2 | device BCD |
| 22 | 1 | device class |
| 23 | 1 | device subclass |
| 24 | 1 | device protocol |
| 25 | 1 | bus-id length |
| 26 | 2 | endpoint count |
| 28 | 2 | reserved, zero |
| 30 | 4 | raw descriptor length |

Endpoint records contain interface number, alternate setting, endpoint address,
attributes, max packet size (u16 little-endian), interval, and one reserved zero
byte. Bus-id bytes MUST be non-empty and MUST NOT contain NUL. Raw descriptors
MUST contain at least one byte.

### 6.2 OPEN family and CLOSE

`OPEN` is 16 bytes: lease token then attachment token. `OPEN_OK` is empty.
`OPEN_REJECT` is one u32 status in `[1, 10]`. `CLOSE` is one u64 lease token.

Valid ordering is CAPABILITY then OPEN, followed by exactly one OPEN_OK or
OPEN_REJECT. USB/IP data is legal only after OPEN_OK. CLOSE is terminal.

## 7. USBIP_DATA fragmentation

Every fragment begins with a 32-byte prefix:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | lease token |
| 8 | 8 | opaque PDU id |
| 16 | 4 | complete PDU length |
| 20 | 4 | fragment offset |
| 24 | 4 | chunk length |
| 28 | 4 | reserved, zero |

The chunk follows immediately. Fragments for one PDU MUST be contiguous, use
the same lease token/PDU id/total length, and exactly advance the offset. `MORE`
MUST be set iff bytes remain. Empty chunks, interleaving, overrun, and more than
4096 fragments are fatal. The complete PDU MUST fit the negotiated `max_pdu`.

## 8. USB/IP subset

RUSB v1 forwards USB/IP 1.1.1 control messages (`OP_REQ_DEVLIST`,
`OP_REQ_IMPORT`) and 48-byte URB PDUs (`CMD_SUBMIT`, `CMD_UNLINK`, `RET_SUBMIT`,
`RET_UNLINK`). It supports control, bulk, and interrupt transfers. Isochronous
transfers and unknown commands MUST be rejected deterministically.

`number_of_packets` for non-isochronous transfers is encoded as `-1`; decoders
MAY accept zero and normalize it to zero internally. Endpoint numbers are in
`[0, 15]`. OUT SUBMIT carries exactly `transfer_buffer_length` bytes after the
header; IN SUBMIT carries none. IN RET_SUBMIT carries exactly `actual_length`
bytes; OUT RET_SUBMIT carries none even when `actual_length` is non-zero.
Because USB/IP clears direction in reply headers, an encoder MUST retain the
original SUBMIT direction; a context-free decoder infers it from payload length.

## 9. SUBMIT/UNLINK lifecycle

SUBMIT sequence numbers are unique while in flight. UNLINK references the
target SUBMIT sequence. Every admitted SUBMIT produces exactly one terminal
RET_SUBMIT. Every UNLINK produces exactly one RET_UNLINK. A late platform
completion after synthetic cancellation MUST be ignored and MUST NOT produce a
second reply. All request and byte windows are released exactly once.

## 10. Failure and close behavior

Malformed input, token mismatch, sequence error, replay, and limit violation
make the RUSB session failed; no further data is accepted. Normal shutdown sends
CLOSE, stops accepting work, retires active requests, releases the lease, and
then destroys platform resources. Abrupt transport loss triggers the same local
lease cleanup without requiring a CLOSE from the peer.

## 11. ABI independence

The protocol version does not imply an implementation ABI. The reference C ABI
has its own version and uses `size` plus `version` on extensible structures.
Neither Rust layout nor a native C/C++ struct layout is a wire format.
