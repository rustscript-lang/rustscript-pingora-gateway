use pingora::http::RequestHeader;
use rustscript_pingora_gateway_policy::ScriptedGatewayPolicy;

fn run(label: &str, script: &str, path: &[u8], headers: &[(&str, &str)]) {
    let policy = ScriptedGatewayPolicy::from_source(script).expect("script should compile");
    let mut request = RequestHeader::build("GET", path, None).expect("request should build");
    for (name, value) in headers {
        request
            .insert_header((*name).to_string(), (*value).to_string())
            .expect("header should insert");
    }
    let result = policy
        .evaluate(&mut request)
        .expect("script should evaluate");
    println!(
        "{label}: status={} body={} proxy_events={}",
        result.response.status.as_u16(),
        result.body,
        result.proxy_events.len()
    );
}

fn main() {
    run(
        "http_proxy",
        include_str!("../scripts/http_proxy.rss"),
        b"/proxy?mode=stream",
        &[("x-stream", "1"), ("x-client-id", "paid")],
    );
    run(
        "tls_termination",
        include_str!("../scripts/tls_termination.rss"),
        b"/terminate?x=1",
        &[("x-downstream-scheme", "tcp")],
    );
    run(
        "websocket_proxy",
        include_str!("../scripts/websocket_proxy.rss"),
        b"/ws",
        &[("x-ws-message", "hello-ws")],
    );
    run(
        "transport_matrix",
        include_str!("../scripts/transport_matrix.rss"),
        b"/transport",
        &[],
    );
}
