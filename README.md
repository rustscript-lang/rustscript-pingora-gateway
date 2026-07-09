# rustscript-pingora-gateway-policy

Standalone Pingora integration demo for `pd-vm` / RustScript.

## What it proves

A Pingora gateway can keep the framework and proxy code compiled while moving request, transport, protocol, and response policy into RustScript:

- live `pingora::http::RequestHeader` reads and request mutation
- Pingora-native host namespaces for request, response, upstream exchange, proxy stream, TCP, TLS, and WebSocket policy
- proxy helpers for native forwarding, bridged forwarding, and exchange-backed streams
- TLS termination and raw downstream transport handling expressed through `pingora::tls::*`, `pingora::tcp::*`, and `pingora::downstream::*`
- scripts import only `pingora`; no pd-edge ABI namespace is required

This does not fork or patch Pingora. It depends on the upstream `pingora` crate plus local `pd-vm` / `pd-host-function` paths only.

## Scripts

| script | focus |
|---|---|
| `scripts/gateway_policy.rss` | direct Pingora request/response policy |
| `scripts/http_proxy.rss` | HTTP exchange, streaming body reads, proxy forwarding, rate limit decision |
| `scripts/tls_termination.rss` | raw transport prelude, TLS handshake, downstream HTTP attach |
| `scripts/websocket_proxy.rss` | WebSocket upstream configuration, message round trip, stream bridge |
| `scripts/transport_matrix.rss` | TCP and TLS host calls in one policy |

## Run

```bash
cargo test --tests --jobs 4
cargo run --example decision
cargo run --example protocols
```
