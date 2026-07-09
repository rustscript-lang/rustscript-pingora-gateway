# rustscript-pingora-gateway-policy

Standalone Pingora integration demo for `pd-vm` / RustScript.

## What it proves

A Pingora gateway can keep the framework and proxy code compiled while moving request, transport, protocol, and response policy into RustScript:

- live `pingora::http::RequestHeader` reads and request mutation
- HTTP request/response/exchange host functions compatible with the `pd-edge` examples
- proxy stream functions for native forwarding, bridged forwarding, and exchange-backed streams
- TCP, UDP, TLS termination, WebSocket, and WebRTC-style host functions for protocol policy demos
- host function names are bound in the same namespaces used by the `.rss` scripts: `http`, `proxy`, `tcp`, `udp`, `tls`, `websocket`, `webrtc`, `rate_limit`, and compatibility `pingora::*` names

This does not fork or patch Pingora. It depends on the upstream `pingora` crate plus local `pd-vm` / `pd-host-function` paths only.

## Scripts

| script | focus |
|---|---|
| `scripts/gateway_policy.rss` | direct Pingora request/response policy |
| `scripts/http_proxy.rss` | HTTP exchange, streaming body reads, proxy forwarding, rate limit decision |
| `scripts/tls_termination.rss` | raw transport prelude, TLS handshake, downstream HTTP attach |
| `scripts/websocket_proxy.rss` | WebSocket upstream configuration, message round trip, stream bridge |
| `scripts/transport_matrix.rss` | TCP, TLS, UDP, and WebRTC-style host calls in one policy |

## Run

```bash
cargo test --tests --jobs 4
cargo run --example decision
cargo run --example protocols
```
