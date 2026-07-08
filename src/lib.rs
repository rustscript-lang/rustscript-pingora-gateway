use pingora::http::{RequestHeader, ResponseHeader};
use vm::{Value, Vm, VmStatus, compile_source};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayDecision {
    Allow,
    Route(String),
    Deny { status: u16, reason: String },
}

#[derive(Debug, Clone)]
pub struct ScriptedGatewayPolicy {
    source: String,
}

impl ScriptedGatewayPolicy {
    pub fn from_source(source: impl Into<String>) -> Result<Self, String> {
        let source = source.into();
        run_string(&wrap_request_source(&source, "GET", "/", ""))?;
        Ok(Self { source })
    }

    pub fn evaluate_request(&self, request: &RequestHeader) -> Result<GatewayDecision, String> {
        let method = request.method.as_str();
        let path = String::from_utf8_lossy(request.raw_path());
        let tier = request
            .headers
            .get("x-user-tier")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let output = run_string(&wrap_request_source(&self.source, method, &path, tier))?;
        parse_decision(&output)
    }

    pub fn deny_response(decision: &GatewayDecision) -> Result<Option<ResponseHeader>, String> {
        match decision {
            GatewayDecision::Deny { status, reason } => {
                let mut response = ResponseHeader::build(*status, Some(1))
                    .map_err(|err| format!("failed to build Pingora response: {err}"))?;
                response
                    .insert_header("x-rustscript-deny-reason", reason.as_str())
                    .map_err(|err| format!("failed to insert Pingora response header: {err}"))?;
                Ok(Some(response))
            }
            GatewayDecision::Allow | GatewayDecision::Route(_) => Ok(None),
        }
    }
}

fn parse_decision(output: &str) -> Result<GatewayDecision, String> {
    if output == "allow" {
        return Ok(GatewayDecision::Allow);
    }
    if let Some(upstream) = output.strip_prefix("route:") {
        return Ok(GatewayDecision::Route(upstream.to_string()));
    }
    if let Some(rest) = output.strip_prefix("deny:") {
        let (status, reason) = rest
            .split_once(':')
            .ok_or_else(|| format!("invalid deny decision '{output}'"))?;
        let status = status
            .parse::<u16>()
            .map_err(|err| format!("invalid deny status '{status}': {err}"))?;
        return Ok(GatewayDecision::Deny {
            status,
            reason: reason.to_string(),
        });
    }
    Err(format!("unknown gateway decision '{output}'"))
}

fn wrap_request_source(policy: &str, method: &str, path: &str, tier: &str) -> String {
    format!(
        "let method = {};\nlet path = {};\nlet tier = {};\n{}",
        rss_string(method),
        rss_string(path),
        rss_string(tier),
        policy
    )
}

fn run_string(source: &str) -> Result<String, String> {
    match run_value(source)? {
        Value::String(value) => Ok(value.as_str().to_string()),
        other => Err(format!("script returned {other:?}; expected string")),
    }
}

fn run_value(source: &str) -> Result<Value, String> {
    let compiled = compile_source(source).map_err(|err| err.to_string())?;
    let mut vm = Vm::new(compiled.program);
    let status = vm.run().map_err(|err| err.to_string())?;
    if status != VmStatus::Halted {
        return Err(format!("script did not halt: {status:?}"));
    }
    vm.stack()
        .last()
        .cloned()
        .ok_or_else(|| "script returned an empty stack".to_string())
}

fn rss_string(value: &str) -> String {
    format!("{value:?}")
}
