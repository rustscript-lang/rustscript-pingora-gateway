use pingora::http::RequestHeader;
use pretty_assertions::assert_eq;
use rustscript_pingora_gateway_policy::{GatewayDecision, ScriptedGatewayPolicy};

#[test]
fn rustscript_denies_pingora_admin_request_for_free_tier() {
    let policy = ScriptedGatewayPolicy::from_source(include_str!("../scripts/gateway_policy.rss"))
        .expect("policy should compile");
    let mut request = RequestHeader::build("GET", b"/admin", None).expect("request should build");
    request
        .insert_header("x-user-tier", "free")
        .expect("header should insert");

    let decision = policy
        .evaluate_request(&request)
        .expect("policy should evaluate");

    assert_eq!(
        decision,
        GatewayDecision::Deny {
            status: 403,
            reason: "upgrade required".to_string(),
        }
    );
}

#[test]
fn rustscript_routes_pingora_canary_request_without_framework_fork() {
    let policy = ScriptedGatewayPolicy::from_source(include_str!("../scripts/gateway_policy.rss"))
        .expect("policy should compile");
    let request = RequestHeader::build("GET", b"/canary", None).expect("request should build");

    let decision = policy
        .evaluate_request(&request)
        .expect("policy should evaluate");

    assert_eq!(
        decision,
        GatewayDecision::Route("canary-upstream".to_string())
    );
}
