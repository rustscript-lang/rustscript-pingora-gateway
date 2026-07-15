# rustscript-pingora-gateway

A runnable Pingora reverse proxy whose request policy is evaluated by RustScript through `pd-vm`.

## Real network path

The `gateway` binary starts a Pingora `Server`, registers an HTTP proxy service with `http_proxy_service`, listens on a TCP socket, and returns a real `HttpPeer` for the configured upstream. The request path is:

```text
HTTP client -> Pingora listener -> RustScript request policy -> Pingora HttpPeer -> upstream TCP server
```

RustScript receives the `RequestHeader` owned by the accepted Pingora `Session`. It can:

- read the live method, path, and headers through `pingora::request::*`
- mutate the request before Pingora sends it upstream
- stop a request with a local response, such as the `/admin` 403 policy
- add headers to the real upstream response before Pingora writes it downstream

The project depends on the upstream `pingora` crate with its `proxy` feature. It does not fork or patch Pingora.

## Supported RustScript host API

Every bound host below reads or mutates the live Pingora `RequestHeader` or `ResponseHeader`. Names follow the corresponding Pingora header fields and methods:

| RustScript host | Pingora operation |
| --- | --- |
| `pingora::request::method` | `RequestHeader.method` |
| `pingora::request::path` | `RequestHeader.uri.path()` |
| `pingora::request::query` | `RequestHeader.uri.query()` |
| `pingora::request::uri` | `RequestHeader.uri` |
| `pingora::request::version` | `RequestHeader.version` |
| `pingora::request::header` | `RequestHeader.headers.get()` |
| `pingora::request::insert_header` | `RequestHeader::insert_header()` |
| `pingora::request::append_header` | `RequestHeader::append_header()` |
| `pingora::request::remove_header` | `RequestHeader::remove_header()` |
| `pingora::request::set_method` | `RequestHeader::set_method()` |
| `pingora::request::set_uri` | `RequestHeader::set_uri()` |
| `pingora::response::status` | `ResponseHeader.status` |
| `pingora::response::set_status` | `ResponseHeader::set_status()` |
| `pingora::response::header` | `ResponseHeader.headers.get()` |
| `pingora::response::insert_header` | `ResponseHeader::insert_header()` |
| `pingora::response::append_header` | `ResponseHeader::append_header()` |
| `pingora::response::remove_header` | `ResponseHeader::remove_header()` |

The gateway deliberately does not bind the old modeled `request::id`, `request::scheme`, `request::client_ip`, `request::port`, `tcp`, `tls`, `websocket`, `upstream::send`, or `proxy::pipe` APIs. Their implementations returned hard-coded metadata or changed only in-memory fixture state. Request and response body I/O is also omitted because Pingora exposes it asynchronously through the session and `ProxyHttp` lifecycle. Those operations cannot be implemented truthfully inside the synchronous policy VM host-call boundary.

The policy bytecode is compiled once when the gateway starts. Each request runs a fresh VM with JIT disabled and a fixed fuel budget. Script host calls reject framing and hop-by-hop headers such as `Content-Length`, `Transfer-Encoding`, and `Connection`; local empty responses are emitted with `Content-Length: 0` so the downstream connection can be reused.

## Run a live proxy

Start any local HTTP server as the upstream:

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

Start the Pingora gateway in another terminal:

```bash
cargo run --bin gateway -- \
  --listen 127.0.0.1:6191 \
  --upstream 127.0.0.1:8080 \
  --script scripts/gateway_policy.rss
```

Send requests through Pingora:

```bash
curl -i http://127.0.0.1:6191/canary
curl -i http://127.0.0.1:6191/admin -H 'x-user-tier: free'
```

The first request reaches the upstream after RustScript inserts `x-rustscript-checked: true`. The second receives a RustScript-controlled 403 before any upstream connection is opened.

## Verification

```bash
cargo test --test gateway_policy
cargo test --test live_proxy -- --nocapture
cargo clippy --all-targets -- -D warnings
```

`tests/live_proxy.rs` binds two real loopback sockets, launches the compiled Pingora gateway process, sends downstream HTTP requests, and records the bytes received by the upstream socket. It verifies that:

- denied traffic never reaches the upstream listener
- a denied response and a forwarded request can share one downstream keep-alive connection
- allowed traffic is forwarded by Pingora
- the upstream receives the RustScript-added request header
- the client receives the real upstream body and headers
- RustScript response headers are applied to the proxied response

The direct `RequestHeader` tests remain as focused policy unit tests; the loopback test supplies the network-level proof.

## Script

See [`scripts/gateway_policy.rss`](scripts/gateway_policy.rss).
