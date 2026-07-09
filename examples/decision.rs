use pingora::http::RequestHeader;
use rustscript_pingora_gateway_policy::ScriptedGatewayPolicy;

fn main() {
    let policy = ScriptedGatewayPolicy::from_source(include_str!("../scripts/gateway_policy.rss"))
        .expect("policy should compile");
    let mut request = RequestHeader::build("GET", b"/admin", None).expect("request should build");
    request
        .insert_header("x-user-tier", "free")
        .expect("tier header should insert");

    let response = policy
        .evaluate_request(&mut request)
        .expect("policy should evaluate");
    let reason = response
        .headers
        .get("x-rustscript-deny-reason")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    println!(
        "status={}, reason={}, request_checked={}",
        response.status.as_u16(),
        reason,
        request
            .headers
            .get("x-rustscript-checked")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    );
}
