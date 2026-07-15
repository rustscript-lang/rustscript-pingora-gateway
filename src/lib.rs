use std::{cell::RefCell, collections::HashSet, net::SocketAddr};

use async_trait::async_trait;
use pingora::{
    Error, ErrorType, Result as PingoraResult,
    http::{RequestHeader, ResponseHeader},
    proxy::{ProxyHttp, Session},
    upstreams::peer::HttpPeer,
};
pub(crate) use vm::Vm;
use vm::{
    CallOutcome, CallReturn, JitConfig, Program, Value, VmError, VmResult, VmStatus, compile_source,
};

const POLICY_FUEL: u64 = 1_000_000;

#[derive(Debug, Clone)]
pub struct ScriptedGatewayPolicy {
    program: Program,
}

impl ScriptedGatewayPolicy {
    pub fn from_source(source: impl Into<String>) -> Result<Self, String> {
        let source = source.into();
        let compiled = compile_source(&source).map_err(|err| err.to_string())?;
        Ok(Self {
            program: compiled.program,
        })
    }

    pub fn evaluate_request(&self, request: &mut RequestHeader) -> Result<ResponseHeader, String> {
        let mut response = ResponseHeader::build(200, Some(8))
            .map_err(|err| format!("failed to build Pingora response: {err}"))?;
        with_gateway_context(request, &mut response, || run_policy(&self.program))?;
        Ok(response)
    }
}

#[derive(Debug, Default)]
pub struct RequestContext {
    response_headers: Vec<(String, String)>,
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
            .evaluate_request(session.as_downstream_mut().req_header_mut())
            .map_err(|err| Error::explain(ErrorType::InternalError, err))?;

        ctx.response_headers = policy_response
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
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
            let result = if inserted.insert(name.to_ascii_lowercase()) {
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

#[derive(Clone, Copy)]
struct GatewayContext {
    request: *mut RequestHeader,
    response: *mut ResponseHeader,
}

thread_local! {
    static GATEWAY_CONTEXT: RefCell<Option<GatewayContext>> = const { RefCell::new(None) };
}

struct GatewayContextGuard;

impl Drop for GatewayContextGuard {
    fn drop(&mut self) {
        GATEWAY_CONTEXT.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

fn with_gateway_context<T>(
    request: &mut RequestHeader,
    response: &mut ResponseHeader,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    GATEWAY_CONTEXT.with(|slot| {
        *slot.borrow_mut() = Some(GatewayContext { request, response });
    });
    let _guard = GatewayContextGuard;
    f()
}

fn with_request<T>(f: impl FnOnce(&mut RequestHeader) -> VmResult<T>) -> VmResult<T> {
    GATEWAY_CONTEXT.with(|slot| {
        let ctx = slot
            .borrow()
            .ok_or_else(|| VmError::HostError("missing Pingora request context".to_string()))?;
        // SAFETY: the pointer is installed only for the synchronous VM run in evaluate_request.
        unsafe { f(&mut *ctx.request) }
    })
}

fn with_response<T>(f: impl FnOnce(&mut ResponseHeader) -> VmResult<T>) -> VmResult<T> {
    GATEWAY_CONTEXT.with(|slot| {
        let ctx = slot
            .borrow()
            .ok_or_else(|| VmError::HostError("missing Pingora response context".to_string()))?;
        // SAFETY: the pointer is installed only for the synchronous VM run in evaluate_request.
        unsafe { f(&mut *ctx.response) }
    })
}

fn run_policy(program: &Program) -> Result<(), String> {
    let mut vm = Vm::new(program.clone());
    vm.set_jit_config(JitConfig {
        enabled: false,
        ..JitConfig::default()
    });
    vm.set_fuel(POLICY_FUEL);
    bind_pingora_hosts(&mut vm);
    let status = vm.run().map_err(|err| err.to_string())?;
    if status != VmStatus::Halted {
        return Err(format!(
            "script did not halt within fuel budget: status={status:?}, remaining={:?}",
            vm.get_fuel()
        ));
    }
    Ok(())
}

fn ensure_script_header_allowed(name: &str) -> VmResult<()> {
    let normalized = name.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "connection"
            | "content-length"
            | "expect"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) {
        return Err(VmError::HostError(format!(
            "RustScript cannot modify framing or hop-by-hop header: {name}"
        )));
    }
    Ok(())
}

fn bind_pingora_hosts(vm: &mut Vm) {
    vm.bind_static_args_function(
        "pingora::request::method",
        host::pingora::request_method_host,
    );
    vm.bind_static_args_function("pingora::request::path", host::pingora::request_path_host);
    vm.bind_static_args_function("pingora::request::query", host::pingora::request_query_host);
    vm.bind_static_args_function("pingora::request::uri", host::pingora::request_uri_host);
    vm.bind_static_args_function(
        "pingora::request::version",
        host::pingora::request_version_host,
    );
    vm.bind_static_args_function(
        "pingora::request::header",
        host::pingora::request_header_host,
    );
    vm.bind_static_args_function(
        "pingora::request::insert_header",
        host::pingora::request_insert_header_host,
    );
    vm.bind_static_args_function(
        "pingora::request::append_header",
        host::pingora::request_append_header_host,
    );
    vm.bind_static_args_function(
        "pingora::request::remove_header",
        host::pingora::request_remove_header_host,
    );
    vm.bind_static_args_function(
        "pingora::request::set_method",
        host::pingora::request_set_method_host,
    );
    vm.bind_static_args_function(
        "pingora::request::set_uri",
        host::pingora::request_set_uri_host,
    );
    vm.bind_static_args_function(
        "pingora::response::set_status",
        host::pingora::response_set_status_host,
    );
    vm.bind_static_args_function(
        "pingora::response::status",
        host::pingora::response_status_host,
    );
    vm.bind_static_args_function(
        "pingora::response::insert_header",
        host::pingora::response_insert_header_host,
    );
    vm.bind_static_args_function(
        "pingora::response::append_header",
        host::pingora::response_append_header_host,
    );
    vm.bind_static_args_function(
        "pingora::response::remove_header",
        host::pingora::response_remove_header_host,
    );
    vm.bind_static_args_function(
        "pingora::response::header",
        host::pingora::response_header_host,
    );
}

mod host {
    use super::*;
    use pd_host_function::pd_host_function;

    pub(super) trait BorrowVmValue<'a>: Sized {
        fn borrow_vm_value(value: &'a Value, label: &str) -> VmResult<Self>;
    }

    pub(super) fn borrow_arg<'a, T>(args: &'a [Value], index: usize, label: &str) -> VmResult<T>
    where
        T: BorrowVmValue<'a>,
    {
        let value = args
            .get(index)
            .ok_or_else(|| VmError::HostError(format!("missing argument: {label}")))?;
        T::borrow_vm_value(value, label)
    }

    impl<'a> BorrowVmValue<'a> for &'a str {
        fn borrow_vm_value(value: &'a Value, _label: &str) -> VmResult<Self> {
            match value {
                Value::String(text) => Ok(text.as_str()),
                _ => Err(VmError::TypeMismatch("string")),
            }
        }
    }

    impl BorrowVmValue<'_> for i64 {
        fn borrow_vm_value(value: &Value, _label: &str) -> VmResult<Self> {
            match value {
                Value::Int(value) => Ok(*value),
                _ => Err(VmError::TypeMismatch("int")),
            }
        }
    }

    trait IntoVmValue {
        fn into_vm_value(self) -> Value;
    }

    impl IntoVmValue for String {
        fn into_vm_value(self) -> Value {
            Value::string(self)
        }
    }

    impl IntoVmValue for bool {
        fn into_vm_value(self) -> Value {
            Value::Bool(self)
        }
    }

    impl IntoVmValue for i64 {
        fn into_vm_value(self) -> Value {
            Value::Int(self)
        }
    }

    fn return_one<T: IntoVmValue>(value: VmResult<T>) -> VmResult<CallOutcome> {
        Ok(CallOutcome::Return(CallReturn::one(value?.into_vm_value())))
    }

    pub(super) mod pingora {
        use super::*;

        /// Returns the live Pingora request method.
        #[pd_host_function(name = "pingora::request::method")]
        pub(super) fn request_method_impl() -> VmResult<String> {
            with_request(|request| Ok(request.method.as_str().to_string()))
        }

        pub(crate) fn request_method_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_method(args))
        }

        /// Returns the path component of the live Pingora request URI.
        #[pd_host_function(name = "pingora::request::path")]
        pub(super) fn request_path_impl() -> VmResult<String> {
            with_request(|request| Ok(request.uri.path().to_string()))
        }

        pub(crate) fn request_path_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_path(args))
        }

        /// Returns the query component of the live Pingora request URI.
        #[pd_host_function(name = "pingora::request::query")]
        pub(super) fn request_query_impl() -> VmResult<String> {
            with_request(|request| Ok(request.uri.query().unwrap_or("").to_string()))
        }

        pub(crate) fn request_query_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_query(args))
        }

        /// Returns the live Pingora request URI.
        #[pd_host_function(name = "pingora::request::uri")]
        pub(super) fn request_uri_impl() -> VmResult<String> {
            with_request(|request| Ok(request.uri.to_string()))
        }

        pub(crate) fn request_uri_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_uri(args))
        }

        /// Returns the HTTP version of the live Pingora request.
        #[pd_host_function(name = "pingora::request::version")]
        pub(super) fn request_version_impl() -> VmResult<String> {
            with_request(|request| Ok(format!("{:?}", request.version)))
        }

        pub(crate) fn request_version_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_version(args))
        }

        /// Reads a header from the live Pingora request.
        #[pd_host_function(name = "pingora::request::header")]
        pub(super) fn request_header_impl(name: &str) -> VmResult<String> {
            with_request(|request| {
                Ok(request
                    .headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .to_string())
            })
        }

        pub(crate) fn request_header_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_header(args))
        }

        /// Calls Pingora RequestHeader::insert_header on the live request.
        #[pd_host_function(name = "pingora::request::insert_header")]
        pub(super) fn request_insert_header_impl(name: &str, value: &str) -> VmResult<bool> {
            ensure_script_header_allowed(name)?;
            with_request(|request| {
                request
                    .insert_header(name.to_string(), value.to_string())
                    .map_err(|err| {
                        VmError::HostError(format!("Pingora request insert_header: {err}"))
                    })?;
                Ok(true)
            })
        }

        pub(crate) fn request_insert_header_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_insert_header(args))
        }

        /// Calls Pingora RequestHeader::append_header on the live request.
        #[pd_host_function(name = "pingora::request::append_header")]
        pub(super) fn request_append_header_impl(name: &str, value: &str) -> VmResult<bool> {
            ensure_script_header_allowed(name)?;
            with_request(|request| {
                request
                    .append_header(name.to_string(), value.to_string())
                    .map_err(|err| {
                        VmError::HostError(format!("Pingora request append_header: {err}"))
                    })
            })
        }

        pub(crate) fn request_append_header_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_append_header(args))
        }

        /// Calls Pingora RequestHeader::remove_header on the live request.
        #[pd_host_function(name = "pingora::request::remove_header")]
        pub(super) fn request_remove_header_impl(name: &str) -> VmResult<bool> {
            ensure_script_header_allowed(name)?;
            with_request(|request| Ok(request.remove_header(name).is_some()))
        }

        pub(crate) fn request_remove_header_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_remove_header(args))
        }

        /// Calls Pingora RequestHeader::set_method on the live request.
        #[pd_host_function(name = "pingora::request::set_method")]
        pub(super) fn request_set_method_impl(method: &str) -> VmResult<bool> {
            with_request(|request| {
                let method = method.parse().map_err(|err| {
                    VmError::HostError(format!("Pingora request invalid method: {err}"))
                })?;
                request.set_method(method);
                Ok(true)
            })
        }

        pub(crate) fn request_set_method_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_set_method(args))
        }

        /// Calls Pingora RequestHeader::set_uri on the live request.
        #[pd_host_function(name = "pingora::request::set_uri")]
        pub(super) fn request_set_uri_impl(uri: &str) -> VmResult<bool> {
            with_request(|request| {
                let uri = uri.parse().map_err(|err| {
                    VmError::HostError(format!("Pingora request invalid URI: {err}"))
                })?;
                request.set_uri(uri);
                Ok(true)
            })
        }

        pub(crate) fn request_set_uri_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_set_uri(args))
        }

        /// Calls Pingora ResponseHeader::set_status on the live response.
        #[pd_host_function(name = "pingora::response::set_status")]
        pub(super) fn response_set_status_impl(status: i64) -> VmResult<bool> {
            let status = u16::try_from(status)
                .map_err(|err| VmError::HostError(format!("invalid status: {err}")))?;
            with_response(|response| {
                response.set_status(status).map_err(|err| {
                    VmError::HostError(format!("Pingora response set_status: {err}"))
                })?;
                Ok(true)
            })
        }

        pub(crate) fn response_set_status_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(response_set_status(args))
        }

        /// Returns the live Pingora response status code.
        #[pd_host_function(name = "pingora::response::status")]
        pub(super) fn response_status_impl() -> VmResult<i64> {
            with_response(|response| Ok(i64::from(response.status.as_u16())))
        }

        pub(crate) fn response_status_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(response_status(args))
        }

        /// Reads a header from the live Pingora response.
        #[pd_host_function(name = "pingora::response::header")]
        pub(super) fn response_header_impl(name: &str) -> VmResult<String> {
            with_response(|response| {
                Ok(response
                    .headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .to_string())
            })
        }

        pub(crate) fn response_header_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(response_header(args))
        }

        /// Calls Pingora ResponseHeader::insert_header on the live response.
        #[pd_host_function(name = "pingora::response::insert_header")]
        pub(super) fn response_insert_header_impl(name: &str, value: &str) -> VmResult<bool> {
            ensure_script_header_allowed(name)?;
            with_response(|response| {
                response
                    .insert_header(name.to_string(), value.to_string())
                    .map_err(|err| {
                        VmError::HostError(format!("Pingora response insert_header: {err}"))
                    })?;
                Ok(true)
            })
        }

        pub(crate) fn response_insert_header_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(response_insert_header(args))
        }

        /// Calls Pingora ResponseHeader::append_header on the live response.
        #[pd_host_function(name = "pingora::response::append_header")]
        pub(super) fn response_append_header_impl(name: &str, value: &str) -> VmResult<bool> {
            ensure_script_header_allowed(name)?;
            with_response(|response| {
                response
                    .append_header(name.to_string(), value.to_string())
                    .map_err(|err| {
                        VmError::HostError(format!("Pingora response append_header: {err}"))
                    })
            })
        }

        pub(crate) fn response_append_header_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(response_append_header(args))
        }

        /// Calls Pingora ResponseHeader::remove_header on the live response.
        #[pd_host_function(name = "pingora::response::remove_header")]
        pub(super) fn response_remove_header_impl(name: &str) -> VmResult<bool> {
            ensure_script_header_allowed(name)?;
            with_response(|response| Ok(response.remove_header(name).is_some()))
        }

        pub(crate) fn response_remove_header_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(response_remove_header(args))
        }
    }
}
