use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use pingora::{
    Error, ErrorType, Result as PingoraResult,
    http::{RequestHeader, ResponseHeader},
    proxy::{ProxyHttp, Session},
    upstreams::peer::HttpPeer,
};
use vm::{
    CompileSourceFileOptions, HostApiCatalog, JitConfig, Program, SourceFlavor, Vm, VmStatus,
    compile_source_with_flavor_and_options,
};

mod host;

pub use host::pingora_host_catalog;
pub(crate) use vm::{Value, VmResult};

use host::{PingoraPolicySession, bind_pingora_hosts, pingora_host_modules};

const POLICY_FUEL: u64 = 1_000_000;

#[derive(Debug, Clone)]
pub struct ScriptedGatewayPolicy {
    program: Program,
}

impl ScriptedGatewayPolicy {
    pub fn from_source(source: impl Into<String>) -> Result<Self, String> {
        let source = source.into();
        let compiled = compile_source_with_flavor_and_options(
            &source,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::new().with_host_api_catalog(pingora_host_catalog()),
        )
        .map_err(|err| err.to_string())?;
        Ok(Self {
            program: compiled.program,
        })
    }

    pub fn evaluate_request(&self, request: &mut RequestHeader) -> Result<ResponseHeader, String> {
        self.evaluate_request_on(request, None)
    }

    pub(crate) fn evaluate_request_on(
        &self,
        request: &mut RequestHeader,
        upstream: Option<SocketAddr>,
    ) -> Result<ResponseHeader, String> {
        let mut response = ResponseHeader::build(200, Some(8))
            .map_err(|err| format!("failed to build Pingora response: {err}"))?;
        run_policy(
            &self.program,
            request,
            &mut response,
            upstream.map(|addr| addr.to_string()),
        )?;
        Ok(response)
    }
}

#[derive(Debug, Default)]
pub struct RequestContext {
    response_headers: Vec<(HeaderName, HeaderValue)>,
}

#[derive(Debug, Clone)]
pub struct ScriptedProxy {
    policy: ScriptedGatewayPolicy,
    upstream: SocketAddr,
}

impl ScriptedProxy {
    pub fn new(policy: ScriptedGatewayPolicy, upstream: SocketAddr) -> Self {
        Self { policy, upstream }
    }
}

#[async_trait]
impl ProxyHttp for ScriptedProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::default()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool> {
        let mut policy_response = self
            .policy
            .evaluate_request_on(
                session.as_downstream_mut().req_header_mut(),
                Some(self.upstream),
            )
            .map_err(|err| Error::explain(ErrorType::InternalError, err))?;

        ctx.response_headers = policy_response
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();

        if policy_response.status.as_u16() != 200 {
            policy_response.remove_header("transfer-encoding");
            policy_response
                .insert_header("content-length", "0")
                .map_err(|err| {
                    Error::because(
                        ErrorType::InternalError,
                        "failed to frame local policy response",
                        err,
                    )
                })?;
            session
                .write_response_header(Box::new(policy_response), true)
                .await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(self.upstream, false, String::new())))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        upstream_request
            .insert_header("host", self.upstream.to_string())
            .map_err(|err| {
                Error::because(
                    ErrorType::InternalError,
                    "failed to set upstream Host header",
                    err,
                )
            })?;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        let mut inserted = HashSet::new();
        for (name, value) in &ctx.response_headers {
            let result = if inserted.insert(name.clone()) {
                upstream_response.insert_header(name.clone(), value.clone())
            } else {
                upstream_response
                    .append_header(name.clone(), value.clone())
                    .map(|_| ())
            };
            result.map_err(|err| {
                Error::because(
                    ErrorType::InternalError,
                    "failed to apply RustScript response header",
                    err,
                )
            })?;
        }
        Ok(())
    }
}

fn run_policy(
    program: &Program,
    request: &mut RequestHeader,
    response: &mut ResponseHeader,
    upstream: Option<String>,
) -> Result<(), String> {
    let mut vm = Vm::new(program.clone());
    vm.set_jit_config(JitConfig {
        enabled: false,
        ..JitConfig::default()
    });
    vm.set_fuel(POLICY_FUEL);
    bind_pingora_hosts(&mut vm)?;
    vm.host_context()
        .set_host_state(PingoraPolicySession::new(request, response, upstream))
        .map_err(|err| err.to_string())?;
    let status = vm.run().map_err(|err| err.to_string());
    let _ = vm.host_context().take_host_state::<PingoraPolicySession>();
    let status = status?;
    if status != VmStatus::Halted {
        return Err(format!(
            "script did not halt within fuel budget: status={status:?}, remaining={:?}",
            vm.get_fuel()
        ));
    }
    Ok(())
}

/// Production catalog used to compile and bind every bundled policy.
pub fn pingora_production_catalog() -> Arc<HostApiCatalog> {
    pingora_host_catalog()
}

pub fn pingora_production_modules() -> [vm::HostModuleDescriptor; 4] {
    pingora_host_modules()
}
