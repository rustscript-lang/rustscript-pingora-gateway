use pingora::http::RequestHeader;
use pretty_assertions::assert_eq;
use rustscript_pingora_gateway_policy::ScriptedGatewayPolicy;

fn header(response: &pingora::http::ResponseHeader, name: &str) -> String {
    response
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn policy(script: &str) -> ScriptedGatewayPolicy {
    ScriptedGatewayPolicy::from_source(script).expect("policy should compile")
}

#[test]
fn rustscript_controls_pingora_response_for_admin_request() {
    let policy = policy(include_str!("../scripts/gateway_policy.rss"));
    let mut request = RequestHeader::build("GET", b"/admin", None).expect("request should build");
    request
        .insert_header("x-user-tier", "free")
        .expect("header should insert");

    let response = policy
        .evaluate_request(&mut request)
        .expect("policy should evaluate");

    assert_eq!(response.status.as_u16(), 403);
    assert_eq!(
        header(&response, "x-rustscript-deny-reason"),
        "upgrade required"
    );
    assert_eq!(
        request
            .headers
            .get("x-rustscript-checked")
            .and_then(|value| value.to_str().ok())
            .unwrap_or(""),
        "true"
    );
}

#[test]
fn rustscript_controls_pingora_response_headers_for_canary_route() {
    let policy = policy(include_str!("../scripts/gateway_policy.rss"));
    let mut request = RequestHeader::build("GET", b"/canary", None).expect("request should build");

    let response = policy
        .evaluate_request(&mut request)
        .expect("policy should evaluate");

    assert_eq!(response.status.as_u16(), 200);
    assert_eq!(
        header(&response, "x-rustscript-upstream"),
        "canary-upstream"
    );
}

#[test]
fn http_proxy_script_covers_exchange_streaming_and_proxy_paths() {
    let policy = policy(include_str!("../scripts/http_proxy.rss"));
    let mut streaming =
        RequestHeader::build("GET", b"/proxy?mode=stream", None).expect("request should build");
    streaming
        .insert_header("x-stream", "1")
        .expect("header should insert");
    streaming
        .insert_header("x-client-id", "paid")
        .expect("header should insert");

    let streamed = policy
        .evaluate(&mut streaming)
        .expect("streaming proxy should evaluate");
    assert_eq!(streamed.response.status.as_u16(), 200);
    assert_eq!(
        header(&streamed.response, "x-rustscript-action"),
        "streaming-proxy"
    );
    assert!(
        streamed
            .body
            .contains("proxied http://127.0.0.1:18080/proxy")
    );

    let mut native = RequestHeader::build("GET", b"/proxy", None).expect("request should build");
    native
        .insert_header("x-client-id", "paid")
        .expect("header should insert");
    let proxied = policy
        .evaluate(&mut native)
        .expect("native proxy should evaluate");
    assert_eq!(
        header(&proxied.response, "x-rustscript-action"),
        "native-proxy"
    );
    assert_eq!(header(&proxied.response, "x-proxy-status"), "proxied");
    assert!(!proxied.proxy_events.is_empty());
}

#[test]
fn tls_termination_script_accepts_transport_and_sets_tls_metadata() {
    let policy = policy(include_str!("../scripts/tls_termination.rss"));
    let mut request =
        RequestHeader::build("GET", b"/terminate?x=1", None).expect("request should build");
    request
        .insert_header("x-downstream-scheme", "tcp")
        .expect("header should insert");

    let result = policy
        .evaluate(&mut request)
        .expect("termination should evaluate");

    assert_eq!(result.response.status.as_u16(), 201);
    assert_eq!(header(&result.response, "x-termination"), "tls");
    assert_eq!(header(&result.response, "x-tls-alpn"), "h2,http/1.1");
    assert_eq!(result.body, "GET|/terminate?x=1");
}

#[test]
fn websocket_proxy_script_round_trips_text_and_marks_close_phase() {
    let policy = policy(include_str!("../scripts/websocket_proxy.rss"));
    let mut request = RequestHeader::build("GET", b"/ws", None).expect("request should build");
    request
        .insert_header("x-ws-message", "hello-ws")
        .expect("header should insert");

    let result = policy
        .evaluate(&mut request)
        .expect("websocket proxy should evaluate");

    assert_eq!(result.response.status.as_u16(), 200);
    assert_eq!(header(&result.response, "x-ws-protocol"), "chat");
    assert_eq!(header(&result.response, "x-proxy-status"), "proxied");
    assert_eq!(header(&result.response, "x-ws-phase"), "closed");
    assert_eq!(result.body, "hello-ws");
}

#[test]
fn transport_matrix_script_exercises_tcp_and_tls_hosts() {
    let policy = policy(include_str!("../scripts/transport_matrix.rss"));
    let mut request =
        RequestHeader::build("POST", b"/transport", None).expect("request should build");

    let result = policy
        .evaluate(&mut request)
        .expect("transport matrix should evaluate");

    assert_eq!(result.response.status.as_u16(), 200);
    assert_eq!(header(&result.response, "x-tcp-phase"), "connected");
    assert_eq!(header(&result.response, "x-tls-phase"), "handshaked");
    assert_eq!(header(&result.response, "x-tls-alpn"), "edge/1");
    assert_eq!(result.body, "transport matrix ok");
}
