use std::cell::RefCell;

use pingora::http::{RequestHeader, ResponseHeader};
pub(crate) use vm::Vm;
use vm::{CallOutcome, CallReturn, Value, VmError, VmResult, VmStatus, compile_source};

#[derive(Debug, Clone)]
pub struct ScriptedGatewayPolicy {
    source: String,
}

impl ScriptedGatewayPolicy {
    pub fn from_source(source: impl Into<String>) -> Result<Self, String> {
        let source = source.into();
        compile_source(&source).map_err(|err| err.to_string())?;
        Ok(Self { source })
    }

    pub fn evaluate_request(&self, request: &mut RequestHeader) -> Result<ResponseHeader, String> {
        let mut response = ResponseHeader::build(200, Some(8))
            .map_err(|err| format!("failed to build Pingora response: {err}"))?;
        with_gateway_context(request, &mut response, || run_policy(&self.source))?;
        Ok(response)
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

fn run_policy(source: &str) -> Result<(), String> {
    let compiled = compile_source(source).map_err(|err| err.to_string())?;
    let mut vm = Vm::new(compiled.program);
    bind_pingora_hosts(&mut vm);
    let status = vm.run().map_err(|err| err.to_string())?;
    if status != VmStatus::Halted {
        return Err(format!("script did not halt: {status:?}"));
    }
    Ok(())
}

fn bind_pingora_hosts(vm: &mut Vm) {
    vm.bind_static_args_function(
        "pingora::request::method",
        host::pingora::request_method_host,
    );
    vm.bind_static_args_function("pingora::request::path", host::pingora::request_path_host);
    vm.bind_static_args_function(
        "pingora::request::header",
        host::pingora::request_header_host,
    );
    vm.bind_static_args_function(
        "pingora::request::insert_header",
        host::pingora::request_insert_header_host,
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

        /// Returns the live Pingora request path.
        #[pd_host_function(name = "pingora::request::path")]
        pub(super) fn request_path_impl() -> VmResult<String> {
            with_request(|request| Ok(String::from_utf8_lossy(request.raw_path()).into_owned()))
        }

        pub(crate) fn request_path_host(args: &[Value]) -> VmResult<CallOutcome> {
            return_one(request_path(args))
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

        /// Calls Pingora ResponseHeader::insert_header on the live response.
        #[pd_host_function(name = "pingora::response::insert_header")]
        pub(super) fn response_insert_header_impl(name: &str, value: &str) -> VmResult<bool> {
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
    }
}
