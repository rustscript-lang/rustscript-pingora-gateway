# rustscript-pingora-gateway-policy

Standalone Pingora integration demo for `pd-vm` / RustScript.

## What it proves

A Pingora gateway can keep the framework and proxy code compiled while moving request policy into RustScript:

- input from `pingora::http::RequestHeader`: method, path, `x-user-tier`
- scripted output: `allow`, `route:<upstream>`, or `deny:<status>:<reason>`
- optional conversion of deny decisions back into `pingora::http::ResponseHeader`

This does not fork or patch Pingora. It depends on the upstream `pingora` crate and local `pd-vm` path only.

## Run

```bash
cargo test --tests --jobs 4
cargo run --example decision
```

## Script

See `scripts/gateway_policy.rss`.
