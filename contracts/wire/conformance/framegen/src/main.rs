//! Emit the golden wire-frame conformance vectors (`../frames.json`).
//!
//! Each vector is one framed message — `VER(1) | TYPE(1) | LENGTH(u32 BE) | PAYLOAD` — where
//! the payload is the prost serialization of the message named in the frozen catalogue
//! (`agent-gateway-v1.md` §4 / `gateway-relay-v1.md` §4), except `STREAM_DATA` whose payload
//! is raw opaque bytes. The bytes are authoritative because prost is deterministic over the
//! same frozen proto both consumer repos generate from; the framing is the trivially-checked
//! 6-byte header. Every emitted frame is decoded again here as a self-check, and a couple of
//! hand-computable frames are asserted against their known bytes.

// The generated proto modules carry types this tool doesn't construct (e.g. token payloads).
#![allow(dead_code)]

use prost::Message;
use serde::Serialize;

// prost emits cross-package refs as `super::super::controlplane::v1::…`, so the generated
// files must be nested to match their proto package paths.
mod sessionlayer {
    pub mod controlplane {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/sessionlayer.controlplane.v1.rs"));
        }
    }
    pub mod agent {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/sessionlayer.agent.v1.rs"));
        }
    }
    pub mod gateway {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/sessionlayer.gateway.v1.rs"));
        }
    }
}
use sessionlayer::agent::v1 as apb;
use sessionlayer::controlplane::v1 as cpb;
use sessionlayer::gateway::v1 as gpb;

const HEADER_LEN: usize = 6;
const WIRE_VER: u8 = 1;

#[derive(Serialize)]
struct Frame {
    name: &'static str,
    /// Which protocol profile the frame belongs to (shared framing; `gateway-relay` for the
    /// HA relay-only types).
    profile: &'static str,
    ver: u8,
    #[serde(rename = "type")]
    type_byte: u8,
    type_name: &'static str,
    /// The fully-qualified protobuf message the payload decodes as, or `null` for the raw
    /// `STREAM_DATA` payload.
    message: Option<&'static str>,
    /// Human description of the pinned field values (so a reader knows what was encoded).
    fields: &'static str,
    /// The prost payload bytes alone (hex, lower, no separators).
    payload_hex: String,
    /// The complete framed message (hex): `header || payload`.
    frame_hex: String,
}

#[derive(Serialize)]
struct DecodeNegative {
    name: &'static str,
    hex: String,
    /// The `FrameError` variant a conformant decoder MUST return (matches
    /// `agent/wire.rs::FrameError`).
    expect: &'static str,
    note: &'static str,
}

#[derive(Serialize)]
struct Vectors {
    schema: &'static str,
    note: &'static str,
    wire_version: &'static str,
    header: &'static str,
    frames: Vec<Frame>,
    decode_negatives: Vec<DecodeNegative>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn frame_bytes(ver: u8, type_byte: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(ver);
    out.push(type_byte);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build one framed vector from a protobuf payload, self-checking that the header parses
/// back to the same `(ver, type, len)`.
fn pb_frame<M: Message>(
    name: &'static str,
    profile: &'static str,
    type_byte: u8,
    type_name: &'static str,
    message: &'static str,
    fields: &'static str,
    msg: &M,
) -> Frame {
    let payload = msg.encode_to_vec();
    let frame = frame_bytes(WIRE_VER, type_byte, &payload);
    self_check(&frame, type_byte, &payload);
    Frame {
        name,
        profile,
        ver: WIRE_VER,
        type_byte,
        type_name,
        message: Some(message),
        fields,
        payload_hex: hex(&payload),
        frame_hex: hex(&frame),
    }
}

/// A raw-payload frame (`STREAM_DATA`): the payload is opaque bytes, not protobuf.
fn raw_frame(name: &'static str, type_byte: u8, type_name: &'static str, payload: &[u8]) -> Frame {
    let frame = frame_bytes(WIRE_VER, type_byte, payload);
    self_check(&frame, type_byte, payload);
    Frame {
        name,
        profile: "shared",
        ver: WIRE_VER,
        type_byte,
        type_name,
        message: None,
        fields: "raw opaque bytes (SSH-layer ciphertext); NOT protobuf",
        payload_hex: hex(payload),
        frame_hex: hex(&frame),
    }
}

/// Decode the framing back out and assert it matches — a golden frame that does not parse to
/// its own header is a worse-than-useless oracle.
fn self_check(frame: &[u8], type_byte: u8, payload: &[u8]) {
    assert!(frame.len() >= HEADER_LEN, "frame shorter than the header");
    assert_eq!(frame[0], WIRE_VER, "ver byte");
    assert_eq!(frame[1], type_byte, "type byte");
    let len = u32::from_be_bytes([frame[2], frame[3], frame[4], frame[5]]) as usize;
    assert_eq!(len, payload.len(), "length field != payload length");
    assert_eq!(frame.len() - HEADER_LEN, len, "trailing bytes / short body");
    assert_eq!(&frame[HEADER_LEN..], payload, "payload passthrough");
}

fn component() -> cpb::ComponentInfo {
    cpb::ComponentInfo {
        name: "SessionLayer".into(),
        semver: "0.1.0".into(),
        protocol_min: Some(cpb::ProtocolVersion { major: 1, minor: 0 }),
        protocol_max: Some(cpb::ProtocolVersion { major: 1, minor: 0 }),
    }
}

fn main() {
    // Hand-verifiable anchor: Ping{nonce=42} is field 1 (varint) => tag 0x08, value 0x2a.
    // So the payload is `082a` and the frame is `01 10 00000002 082a`. If prost or the
    // framing ever drifts, this assert fails before anything is written.
    let ping = apb::Ping { nonce: 42 };
    assert_eq!(ping.encode_to_vec(), vec![0x08, 0x2a], "prost Ping{{42}} anchor");
    // ver=01, type=10, len=00000002, payload=082a
    assert_eq!(
        hex(&frame_bytes(WIRE_VER, 0x10, &ping.encode_to_vec())),
        "011000000002082a",
    );

    let frames = vec![
        pb_frame(
            "hello",
            "shared",
            0x01,
            "HELLO",
            "sessionlayer.agent.v1.AgentHello",
            "component = {name:SessionLayer, semver:0.1.0, min:1.0, max:1.0}",
            &apb::AgentHello {
                component: Some(component()),
            },
        ),
        pb_frame(
            "hello_ack",
            "shared",
            0x02,
            "HELLO_ACK",
            "sessionlayer.agent.v1.GatewayHelloAck",
            "component=…, selected=1.0, heartbeat_interval_secs=20, max_frame_bytes=65536",
            &apb::GatewayHelloAck {
                component: Some(component()),
                selected: Some(cpb::ProtocolVersion { major: 1, minor: 0 }),
                heartbeat_interval_secs: 20,
                max_frame_bytes: 65536,
            },
        ),
        pb_frame(
            "version_reject",
            "shared",
            0x03,
            "VERSION_REJECT",
            "sessionlayer.agent.v1.VersionReject",
            "gateway_min=1.0, gateway_max=1.0",
            &apb::VersionReject {
                gateway_min: Some(cpb::ProtocolVersion { major: 1, minor: 0 }),
                gateway_max: Some(cpb::ProtocolVersion { major: 1, minor: 0 }),
            },
        ),
        pb_frame(
            "ping",
            "agent",
            0x10,
            "PING",
            "sessionlayer.agent.v1.Ping",
            "nonce=42",
            &apb::Ping { nonce: 42 },
        ),
        pb_frame(
            "pong",
            "agent",
            0x11,
            "PONG",
            "sessionlayer.agent.v1.Pong",
            "nonce=42",
            &apb::Pong { nonce: 42 },
        ),
        pb_frame(
            "dial_back_request",
            "agent",
            0x20,
            "DIAL_BACK_REQUEST",
            "sessionlayer.agent.v1.DialBackRequest",
            "request_id=req-1, node_name=node-a, session_id=sess-1, principal=deploy, gateway_id=gw-a, dial_back_endpoint=wss://gw-a:9444, token=<opaque>, not_after=1700000000",
            &apb::DialBackRequest {
                request_id: "req-1".into(),
                node_name: "node-a".into(),
                session_id: "sess-1".into(),
                principal: "deploy".into(),
                gateway_id: "gw-a".into(),
                dial_back_endpoint: "wss://gw-a:9444".into(),
                token: "SLDB1.PAYLOAD.SIG".into(),
                not_after_epoch_seconds: 1_700_000_000,
            },
        ),
        pb_frame(
            "dial_back_result",
            "agent",
            0x21,
            "DIAL_BACK_RESULT",
            "sessionlayer.agent.v1.DialBackResult",
            "request_id=req-1, accepted=true, error=UNSPECIFIED",
            &apb::DialBackResult {
                request_id: "req-1".into(),
                accepted: true,
                error: apb::DialBackErrorCode::Unspecified as i32,
            },
        ),
        pb_frame(
            "dial_back_auth",
            "agent",
            0x22,
            "DIAL_BACK_AUTH",
            "sessionlayer.agent.v1.DialBackAuth",
            "token=<opaque>, request_id=req-1",
            &apb::DialBackAuth {
                token: "SLDB1.PAYLOAD.SIG".into(),
                request_id: "req-1".into(),
            },
        ),
        pb_frame(
            "dial_back_accept",
            "agent",
            0x23,
            "DIAL_BACK_ACCEPT",
            "sessionlayer.agent.v1.DialBackAccept",
            "(empty)",
            &apb::DialBackAccept {},
        ),
        pb_frame(
            "relay_open",
            "gateway-relay",
            0x24,
            "RELAY_OPEN",
            "sessionlayer.gateway.v1.RelayOpen",
            "token=<opaque SLGW1>",
            &gpb::RelayOpen {
                token: "SLGW1.PAYLOAD.SIG".into(),
            },
        ),
        pb_frame(
            "relay_accept",
            "gateway-relay",
            0x25,
            "RELAY_ACCEPT",
            "sessionlayer.gateway.v1.RelayAccept",
            "(empty)",
            &gpb::RelayAccept {},
        ),
        pb_frame(
            "relay_reject",
            "gateway-relay",
            0x26,
            "RELAY_REJECT",
            "sessionlayer.gateway.v1.RelayReject",
            "code=stale_nonce, message=owner superseded",
            &gpb::RelayReject {
                code: "stale_nonce".into(),
                message: "owner superseded".into(),
            },
        ),
        pb_frame(
            "stream_open",
            "agent",
            0x30,
            "STREAM_OPEN",
            "sessionlayer.agent.v1.StreamOpen",
            "(empty)",
            &apb::StreamOpen {},
        ),
        raw_frame("stream_data", 0x31, "STREAM_DATA", &[0x00, 0x01, 0x02, 0x03, 0xff]),
        pb_frame(
            "stream_close",
            "shared",
            0x32,
            "STREAM_CLOSE",
            "sessionlayer.agent.v1.StreamClose",
            "reason=EOF",
            &apb::StreamClose {
                reason: apb::StreamCloseReason::Eof as i32,
            },
        ),
        pb_frame(
            "wire_error",
            "shared",
            0x7e,
            "ERROR",
            "sessionlayer.agent.v1.WireError",
            "code=PROTOCOL, message=protocol error",
            &apb::WireError {
                code: apb::WireErrorCode::Protocol as i32,
                message: "protocol error".into(),
            },
        ),
    ];

    // Negative decode cases: a conformant decoder MUST reject each with the named error
    // (mapping to `agent/wire.rs::FrameError`). `max_frame_bytes` for the oversized case is
    // the 65536 baseline; the length header alone triggers the rejection (no buffering).
    let decode_negatives = vec![
        DecodeNegative {
            name: "short_header",
            hex: hex(&[0x01, 0x10, 0x00]),
            expect: "Short",
            note: "fewer than the 6 header bytes",
        },
        DecodeNegative {
            name: "length_gt_body",
            hex: hex(&{
                let mut v = frame_bytes(1, 0x31, &[1, 2, 3, 4]);
                v.pop(); // body one byte short of LENGTH
                v
            }),
            expect: "LengthMismatch",
            note: "LENGTH exceeds the remaining message bytes",
        },
        DecodeNegative {
            name: "trailing_garbage",
            hex: hex(&{
                let mut v = frame_bytes(1, 0x31, &[1, 2, 3, 4]);
                v.push(0xff); // one byte past LENGTH
                v
            }),
            expect: "LengthMismatch",
            note: "bytes beyond LENGTH",
        },
        DecodeNegative {
            name: "oversized_by_header",
            hex: hex(&{
                let mut v = vec![0x01u8, 0x31];
                v.extend_from_slice(&(65536u32 + 1).to_be_bytes());
                v // no body: the LENGTH field alone must be rejected, without buffering
            }),
            expect: "TooLarge",
            note: "LENGTH exceeds the negotiated max_frame_bytes (65536); rejected at the header",
        },
        DecodeNegative {
            name: "unknown_type",
            hex: hex(&frame_bytes(1, 0x40, &[])),
            expect: "UnknownType",
            note: "0x40 is reserved (NODE_STATUS), not yet defined",
        },
        DecodeNegative {
            name: "wrong_version",
            hex: hex(&frame_bytes(2, 0x10, &[])),
            expect: "BadVersion",
            note: "VER != the negotiated wire major (1)",
        },
    ];

    let out = Vectors {
        schema: "sessionlayer.wire.conformance/v1",
        note: "Golden wire frames, generated from a known-correct codec (prost over the frozen \
               proto + the frozen 6-byte framing) and self-checked. DO NOT hand-edit — \
               regenerate via `cargo run` in gen/ when the contract changes. Consumed by both \
               Rust repos' CI (see README.md).",
        wire_version: "1.0",
        header: "VER(1) | TYPE(1) | LENGTH(u32 big-endian) | PAYLOAD(LENGTH bytes)",
        frames,
        decode_negatives,
    };

    let json = serde_json::to_string_pretty(&out).expect("serialize vectors");
    let dest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gen/ has a parent (conformance/)")
        .join("frames.json");
    std::fs::write(&dest, json + "\n").expect("write frames.json");
    eprintln!(
        "wrote {} frames + {} negatives to {}",
        out.frames.len(),
        out.decode_negatives.len(),
        dest.display()
    );
}
