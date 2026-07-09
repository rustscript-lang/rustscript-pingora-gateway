# rustscript-pingora-gateway-policy

Standalone Pingora integration demo for `pd-vm` / RustScript.

## What it proves

A Pingora gateway can keep the framework and proxy code compiled while moving request/response policy into RustScript:

- live `pingora::http::RequestHeader` reads: `pingora::request::method`, `pingora::request::path`, `pingora::request::header`
- live Pingora mutations: `pingora::request::insert_header`, `pingora::response::set_status`, `pingora::response::insert_header`
- host functions are exported with `#[pd_host_function(name = "pingora::...")]`; the `.rss` names and namespaces match the bound host names exactly

This does not fork or patch Pingora. It depends on the upstream `pingora` crate plus local `pd-vm` / `pd-host-function` paths only.

## Run

```bash
cargo test --tests --jobs 4
cargo run --example decision
```

## Script

See `scripts/gateway_policy.rss`.
