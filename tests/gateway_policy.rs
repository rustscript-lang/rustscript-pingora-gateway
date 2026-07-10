use pingora::http::RequestHeader;
use pretty_assertions::assert_eq;
use rustscript_pingora_gateway_policy::ScriptedGatewayPolicy;

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
