use pingora::http::RequestHeader;
use rustscript_pingora_gateway_policy::ScriptedGatewayPolicy;

fn main() {
    let policy = ScriptedGatewayPolicy::from_source(include_str!("../scripts/gateway_policy.rss"))
        .expect("policy should compile");
    let mut request = RequestHeader::build("GET", b"/admin", None).expect("request should build");
    request
        .insert_header("x-user-tier", "free")
        .expect("tier header should insert");

    let decision = policy
        .evaluate_request(&request)
        .expect("policy should evaluate");
    println!("{decision:?}");
}
