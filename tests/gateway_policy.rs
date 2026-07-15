use pingora::http::RequestHeader;
use pretty_assertions::assert_eq;
use rustscript_pingora_gateway::ScriptedGatewayPolicy;

#[test]
fn rustscript_controls_pingora_response_for_admin_request() {
    let policy = ScriptedGatewayPolicy::from_source(include_str!("../scripts/gateway_policy.rss"))
        .expect("policy should compile");
    let mut request = RequestHeader::build("GET", b"/admin", None).expect("request should build");
    request
        .insert_header("x-user-tier", "free")
        .expect("header should insert");

    let response = policy
        .evaluate_request(&mut request)
        .expect("policy should evaluate");

    assert_eq!(response.status.as_u16(), 403);
    assert_eq!(
        response
            .headers
            .get("x-rustscript-deny-reason")
            .unwrap()
            .to_str()
            .unwrap(),
        "upgrade required"
    );
    assert_eq!(
        request
            .headers
            .get("x-rustscript-checked")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
}

#[test]
fn rustscript_controls_pingora_response_headers_for_canary_route() {
    let policy = ScriptedGatewayPolicy::from_source(include_str!("../scripts/gateway_policy.rss"))
        .expect("policy should compile");
    let mut request = RequestHeader::build("GET", b"/canary", None).expect("request should build");

    let response = policy
        .evaluate_request(&mut request)
        .expect("policy should evaluate");

    assert_eq!(response.status.as_u16(), 200);
    assert_eq!(
        response
            .headers
            .get("x-rustscript-upstream")
            .unwrap()
            .to_str()
            .unwrap(),
        "loopback-upstream"
    );
}

#[test]
fn rustscript_cannot_override_http_message_framing_headers() {
    for script in [
        r#"
            use pingora;
            pingora::request::insert_header("content-length", "999");
        "#,
        r#"
            use pingora;
            pingora::request::append_header("connection", "close");
        "#,
        r#"
            use pingora;
            pingora::request::remove_header("transfer-encoding");
        "#,
        r#"
            use pingora;
            pingora::response::insert_header("transfer-encoding", "chunked");
        "#,
        r#"
            use pingora;
            pingora::response::append_header("content-length", "999");
        "#,
        r#"
            use pingora;
            pingora::response::remove_header("connection");
        "#,
    ] {
        let policy = ScriptedGatewayPolicy::from_source(script).expect("policy should compile");
        let mut request = RequestHeader::build("GET", b"/", None).expect("request should build");
        let error = policy
            .evaluate_request(&mut request)
            .expect_err("framing header mutation should fail");
        assert!(error.contains("framing or hop-by-hop header"), "{error}");
    }
}

#[test]
fn policy_execution_is_bounded_by_fuel() {
    let policy = ScriptedGatewayPolicy::from_source("while true {}")
        .expect("infinite-loop policy should compile");
    let mut request = RequestHeader::build("GET", b"/", None).expect("request should build");
    let error = policy
        .evaluate_request(&mut request)
        .expect_err("infinite-loop policy should run out of fuel");
    assert!(error.to_ascii_lowercase().contains("fuel"), "{error}");
}

#[test]
fn rustscript_calls_live_pingora_request_and_response_header_apis() {
    let policy = ScriptedGatewayPolicy::from_source(
        r#"
            use pingora;
            let original_path: string = pingora::request::path();
            let original_query: string = pingora::request::query();
            let original_uri: string = pingora::request::uri();
            let version: string = pingora::request::version();
            pingora::request::append_header("x-request-value", "one");
            pingora::request::append_header("x-request-value", "two");
            pingora::request::remove_header("x-remove-me");
            pingora::request::set_method("POST");
            pingora::request::set_uri("/rewritten?source=rustscript");

            pingora::response::insert_header(
                "x-original-target",
                original_path + "?" + original_query
            );
            pingora::response::insert_header("x-original-uri", original_uri);
            pingora::response::insert_header("x-request-version", version);
            pingora::response::append_header("x-response-value", "one");
            pingora::response::append_header("x-response-value", "two");
            let first_response_value: string = pingora::response::header("x-response-value");
            pingora::response::insert_header("x-first-response-value", first_response_value);
            pingora::response::insert_header("x-remove-me", "temporary");
            pingora::response::remove_header("x-remove-me");
            pingora::response::insert_header("x-obs-text", "café");
            pingora::response::status();
        "#,
    )
    .expect("policy should compile");
    let mut request =
        RequestHeader::build("GET", b"/original?foo=bar", None).expect("request should build");
    request
        .insert_header("x-remove-me", "temporary")
        .expect("header should insert");

    let response = policy
        .evaluate_request(&mut request)
        .expect("real Pingora header APIs should evaluate");

    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.raw_path(), b"/rewritten?source=rustscript");
    assert_eq!(request.headers.get_all("x-request-value").iter().count(), 2);
    assert!(!request.headers.contains_key("x-remove-me"));
    assert_eq!(
        response
            .headers
            .get("x-original-target")
            .expect("original target should be copied")
            .to_str()
            .unwrap(),
        "/original?foo=bar"
    );
    assert_eq!(
        response
            .headers
            .get("x-original-uri")
            .expect("original URI should be copied")
            .to_str()
            .unwrap(),
        "/original?foo=bar"
    );
    assert_eq!(
        response
            .headers
            .get("x-request-version")
            .expect("request version should be copied")
            .to_str()
            .unwrap(),
        "HTTP/1.1"
    );
    assert_eq!(
        response.headers.get_all("x-response-value").iter().count(),
        2
    );
    assert_eq!(
        response
            .headers
            .get("x-first-response-value")
            .expect("first appended value should be readable")
            .to_str()
            .unwrap(),
        "one"
    );
    assert!(!response.headers.contains_key("x-remove-me"));
    assert_eq!(
        response
            .headers
            .get("x-obs-text")
            .expect("obs-text header should exist")
            .as_bytes(),
        "café".as_bytes()
    );
}

#[test]
fn pingora_request_mutators_reject_invalid_method_and_uri() {
    for (script, expected) in [
        (
            r#"
                use pingora;
                pingora::request::set_method("bad method");
            "#,
            "invalid method",
        ),
        (
            r#"
                use pingora;
                pingora::request::set_uri("not a uri with spaces");
            "#,
            "invalid uri",
        ),
    ] {
        let policy = ScriptedGatewayPolicy::from_source(script).expect("policy should compile");
        let mut request = RequestHeader::build("GET", b"/", None).expect("request should build");
        let error = policy
            .evaluate_request(&mut request)
            .expect_err("invalid Pingora request mutation should fail");
        assert!(
            error.to_ascii_lowercase().contains(expected),
            "expected {expected:?} in {error:?}"
        );
    }
}

#[test]
fn modeled_or_async_hosts_are_not_exposed_as_pingora_apis() {
    for script in [
        "use pingora; pingora::request::id();",
        "use pingora; pingora::request::scheme();",
        "use pingora; pingora::request::client_ip();",
        "use pingora; pingora::request::port();",
        "use pingora; pingora::request::body();",
        "use pingora; pingora::response::body();",
        "use pingora; pingora::response::set_body(\"body\");",
        "use pingora; pingora::tcp::new();",
        "use pingora; pingora::tls::accept(1);",
        "use pingora; pingora::websocket::new();",
        "use pingora; pingora::upstream::send(1);",
        "use pingora; pingora::proxy::pipe(1, 2);",
        "use pingora; pingora::limits::allow(\"key\");",
        "use pingora; pingora::runtime::sleep(1);",
        "use pingora; pingora::downstream::attach_http();",
    ] {
        let policy = ScriptedGatewayPolicy::from_source(script).expect("policy should compile");
        let mut request = RequestHeader::build("GET", b"/", None).expect("request should build");
        let error = policy
            .evaluate_request(&mut request)
            .expect_err("modeled network API must stay unbound");
        assert!(
            error.contains("unbound host import 'pingora::"),
            "unexpected error for {script:?}: {error}"
        );
    }
}
