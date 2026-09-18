//! Pingora host modules for the policy VM.
//!
//! Guest schemas, adapters, resource/named-struct contracts, and hidden session
//! effects come from `#[pd_host_function]` descriptors. One ordered module list
//! is the only catalog and exact-binding authority.

use std::sync::{Arc, OnceLock};

use pd_host_function::pd_host_function;
use pingora::http::{RequestHeader, ResponseHeader};
use vm::{
    HostApiCatalog, HostFunctionDescriptor, HostFunctionRegistry, HostFunctionSchema,
    HostModuleDescriptor, HostNamedStruct, HostState, HostStateMut, HostStateRef, HostStructField,
    HostTypeSchema, Vm, VmError, VmMap, VmResult, borrow_arg,
};

#[allow(unused_imports)]
use vm::take_arg;

pub(crate) fn pingora_host_modules() -> [HostModuleDescriptor; 4] {
    [
        pingora_request_module(),
        pingora_upstream_module(),
        pingora_response_module(),
        pingora_policy_module(),
    ]
}

/// Guest catalog derived from [`pingora_host_modules`].
pub fn pingora_host_catalog() -> Arc<HostApiCatalog> {
    static CATALOG: OnceLock<Arc<HostApiCatalog>> = OnceLock::new();
    CATALOG
        .get_or_init(|| {
            let descriptors: Vec<HostFunctionDescriptor> = pingora_host_modules()
                .into_iter()
                .flat_map(|module| module.descriptors())
                .collect();
            Arc::new(
                HostFunctionDescriptor::collect_catalog(&descriptors)
                    .expect("pingora host catalog must build from descriptors"),
            )
        })
        .clone()
}

pub(crate) fn bind_pingora_hosts(vm: &mut Vm) -> Result<(), String> {
    let catalog = pingora_host_catalog();
    let mut registry = HostFunctionRegistry::restricted();
    for module in pingora_host_modules() {
        module
            .install_from_catalog(&mut registry, catalog.as_ref())
            .map_err(|error| error.to_string())?;
        module
            .install_state_requirements(vm)
            .map_err(|error| error.to_string())?;
    }
    registry
        .bind_vm_cached(vm)
        .map_err(|error| error.to_string())
}

/// Live Pingora request/response pointers for one policy evaluation.
///
/// Addresses are stored as integers so the host-state table can be `Send`.
/// They are valid only while [`crate::ScriptedGatewayPolicy`] holds the
/// originating headers on the same thread.
pub(crate) struct PingoraPolicySession {
    request: usize,
    response: usize,
    upstream: String,
}

impl HostState for PingoraPolicySession {
    const KEY: &'static str = "pingora.session";

    fn initialize() -> Result<Self, String> {
        Err("Pingora policy session is not installed".to_string())
    }
}

impl PingoraPolicySession {
    pub(crate) fn new(
        request: &mut RequestHeader,
        response: &mut ResponseHeader,
        upstream: Option<String>,
    ) -> Self {
        Self {
            request: request as *mut RequestHeader as usize,
            response: response as *mut ResponseHeader as usize,
            upstream: upstream.unwrap_or_default(),
        }
    }

    fn request(&self) -> VmResult<&RequestHeader> {
        // SAFETY: `run_policy` installs this session only for the synchronous
        // VM run and clears it before the VM is dropped. The request pointer
        // is the `RequestHeader` borrowed by that call.
        let pointer = self.request as *mut RequestHeader;
        if pointer.is_null() {
            return Err(VmError::HostError(
                "missing Pingora request context".to_string(),
            ));
        }
        Ok(unsafe { &*pointer })
    }

    fn request_mut(&mut self) -> VmResult<&mut RequestHeader> {
        let pointer = self.request as *mut RequestHeader;
        if pointer.is_null() {
            return Err(VmError::HostError(
                "missing Pingora request context".to_string(),
            ));
        }
        Ok(unsafe { &mut *pointer })
    }

    fn response(&self) -> VmResult<&ResponseHeader> {
        let pointer = self.response as *mut ResponseHeader;
        if pointer.is_null() {
            return Err(VmError::HostError(
                "missing Pingora response context".to_string(),
            ));
        }
        Ok(unsafe { &*pointer })
    }

    fn response_mut(&mut self) -> VmResult<&mut ResponseHeader> {
        let pointer = self.response as *mut ResponseHeader;
        if pointer.is_null() {
            return Err(VmError::HostError(
                "missing Pingora response context".to_string(),
            ));
        }
        Ok(unsafe { &mut *pointer })
    }
}

pub(crate) struct PingoraRequest;

impl HostNamedStruct for PingoraRequest {
    const NAME: &'static str = "PingoraRequest";

    fn host_struct_fields() -> Vec<HostStructField> {
        vec![
            HostStructField::new("method", HostTypeSchema::String),
            HostStructField::new("path", HostTypeSchema::String),
            HostStructField::new("query", HostTypeSchema::String),
            HostStructField::new("uri", HostTypeSchema::String),
            HostStructField::new("version", HostTypeSchema::String),
        ]
    }
}

pub(crate) struct PingoraUpstream;

impl HostNamedStruct for PingoraUpstream {
    const NAME: &'static str = "PingoraUpstream";

    fn host_struct_fields() -> Vec<HostStructField> {
        vec![HostStructField::new("address", HostTypeSchema::String)]
    }
}

pub(crate) struct PingoraResponse;

impl HostNamedStruct for PingoraResponse {
    const NAME: &'static str = "PingoraResponse";

    fn host_struct_fields() -> Vec<HostStructField> {
        vec![HostStructField::new("status", HostTypeSchema::Int)]
    }
}

pub(crate) struct PingoraPolicy;

impl HostNamedStruct for PingoraPolicy {
    const NAME: &'static str = "PingoraPolicy";

    fn host_struct_fields() -> Vec<HostStructField> {
        vec![HostStructField::new("fuel", HostTypeSchema::Int)]
    }
}

fn named_map(fields: Vec<(&str, vm::Value)>) -> VmMap {
    VmMap::from_entries(
        fields
            .into_iter()
            .map(|(name, value)| (vm::Value::string(name), value))
            .collect(),
    )
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

fn pingora_request_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "pingora.request",
        functions: &[
            request::request_method_descriptor,
            request::request_path_descriptor,
            request::request_query_descriptor,
            request::request_uri_descriptor,
            request::request_version_descriptor,
            request::request_header_descriptor,
            request::request_insert_header_descriptor,
            request::request_append_header_descriptor,
            request::request_remove_header_descriptor,
            request::request_set_method_descriptor,
            request::request_set_uri_descriptor,
            request::request_info_descriptor,
        ],
        resources: &[],
    }
}

fn pingora_upstream_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "pingora.upstream",
        functions: &[upstream::upstream_info_descriptor],
        resources: &[],
    }
}

fn pingora_response_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "pingora.response",
        functions: &[
            response::response_set_status_descriptor,
            response::response_status_descriptor,
            response::response_header_descriptor,
            response::response_insert_header_descriptor,
            response::response_append_header_descriptor,
            response::response_remove_header_descriptor,
            response::response_info_descriptor,
        ],
        resources: &[],
    }
}

fn pingora_policy_module() -> HostModuleDescriptor {
    HostModuleDescriptor {
        name: "pingora.policy",
        functions: &[policy::policy_info_descriptor],
        resources: &[],
    }
}

mod request {
    use super::*;

    /// Returns the live Pingora request method.
    #[pd_host_function(name = "pingora::request::method")]
    pub(super) fn request_method_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
    ) -> VmResult<String> {
        Ok(session.request()?.method.as_str().to_string())
    }

    /// Returns the path component of the live Pingora request URI.
    #[pd_host_function(name = "pingora::request::path")]
    pub(super) fn request_path_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
    ) -> VmResult<String> {
        Ok(session.request()?.uri.path().to_string())
    }

    /// Returns the query component of the live Pingora request URI.
    #[pd_host_function(name = "pingora::request::query")]
    pub(super) fn request_query_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
    ) -> VmResult<String> {
        Ok(session.request()?.uri.query().unwrap_or("").to_string())
    }

    /// Returns the live Pingora request URI.
    #[pd_host_function(name = "pingora::request::uri")]
    pub(super) fn request_uri_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
    ) -> VmResult<String> {
        Ok(session.request()?.uri.to_string())
    }

    /// Returns the HTTP version of the live Pingora request.
    #[pd_host_function(name = "pingora::request::version")]
    pub(super) fn request_version_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
    ) -> VmResult<String> {
        Ok(format!("{:?}", session.request()?.version))
    }

    /// Reads a header from the live Pingora request.
    #[pd_host_function(name = "pingora::request::header")]
    pub(super) fn request_header_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
        name: &str,
    ) -> VmResult<String> {
        Ok(session
            .request()?
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string())
    }

    /// Calls Pingora RequestHeader::insert_header on the live request.
    #[pd_host_function(name = "pingora::request::insert_header")]
    pub(super) fn request_insert_header_impl(
        mut session: HostStateMut<'_, PingoraPolicySession>,
        name: &str,
        value: &str,
    ) -> VmResult<bool> {
        ensure_script_header_allowed(name)?;
        session
            .request_mut()?
            .insert_header(name.to_string(), value.to_string())
            .map_err(|err| VmError::HostError(format!("Pingora request insert_header: {err}")))?;
        Ok(true)
    }

    /// Calls Pingora RequestHeader::append_header on the live request.
    #[pd_host_function(name = "pingora::request::append_header")]
    pub(super) fn request_append_header_impl(
        mut session: HostStateMut<'_, PingoraPolicySession>,
        name: &str,
        value: &str,
    ) -> VmResult<bool> {
        ensure_script_header_allowed(name)?;
        session
            .request_mut()?
            .append_header(name.to_string(), value.to_string())
            .map_err(|err| VmError::HostError(format!("Pingora request append_header: {err}")))
    }

    /// Calls Pingora RequestHeader::remove_header on the live request.
    #[pd_host_function(name = "pingora::request::remove_header")]
    pub(super) fn request_remove_header_impl(
        mut session: HostStateMut<'_, PingoraPolicySession>,
        name: &str,
    ) -> VmResult<bool> {
        ensure_script_header_allowed(name)?;
        Ok(session.request_mut()?.remove_header(name).is_some())
    }

    /// Calls Pingora RequestHeader::set_method on the live request.
    #[pd_host_function(name = "pingora::request::set_method")]
    pub(super) fn request_set_method_impl(
        mut session: HostStateMut<'_, PingoraPolicySession>,
        method: &str,
    ) -> VmResult<bool> {
        let method = method
            .parse()
            .map_err(|err| VmError::HostError(format!("Pingora request invalid method: {err}")))?;
        session.request_mut()?.set_method(method);
        Ok(true)
    }

    /// Calls Pingora RequestHeader::set_uri on the live request.
    #[pd_host_function(name = "pingora::request::set_uri")]
    pub(super) fn request_set_uri_impl(
        mut session: HostStateMut<'_, PingoraPolicySession>,
        uri: &str,
    ) -> VmResult<bool> {
        let uri = uri
            .parse()
            .map_err(|err| VmError::HostError(format!("Pingora request invalid URI: {err}")))?;
        session.request_mut()?.set_uri(uri);
        Ok(true)
    }

    /// Returns the live Pingora request as a named PingoraRequest struct.
    #[pd_host_function(name = "pingora::request::info", contract = request_info_contract)]
    pub(super) fn request_info_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
    ) -> VmResult<VmMap> {
        let request = session.request()?;
        Ok(named_map(vec![
            ("method", vm::Value::string(request.method.as_str())),
            ("path", vm::Value::string(request.uri.path())),
            (
                "query",
                vm::Value::string(request.uri.query().unwrap_or("")),
            ),
            ("uri", vm::Value::string(request.uri.to_string())),
            (
                "version",
                vm::Value::string(format!("{:?}", request.version)),
            ),
        ]))
    }

    fn request_info_contract() -> HostFunctionSchema {
        HostFunctionSchema::with_return(
            "pingora::request::info",
            vec![],
            PingoraRequest::host_type_schema(),
        )
        .with_description("Returns the live Pingora request as a named PingoraRequest struct.")
    }
}

mod upstream {
    use super::*;

    /// Returns the configured upstream peer as a named PingoraUpstream struct.
    #[pd_host_function(name = "pingora::upstream::info", contract = upstream_info_contract)]
    pub(super) fn upstream_info_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
    ) -> VmResult<VmMap> {
        Ok(named_map(vec![(
            "address",
            vm::Value::string(session.upstream.clone()),
        )]))
    }

    fn upstream_info_contract() -> HostFunctionSchema {
        HostFunctionSchema::with_return(
            "pingora::upstream::info",
            vec![],
            PingoraUpstream::host_type_schema(),
        )
        .with_description("Returns the configured upstream peer as a named PingoraUpstream struct.")
    }
}

mod response {
    use super::*;

    /// Calls Pingora ResponseHeader::set_status on the live response.
    #[pd_host_function(name = "pingora::response::set_status")]
    pub(super) fn response_set_status_impl(
        mut session: HostStateMut<'_, PingoraPolicySession>,
        status: i64,
    ) -> VmResult<bool> {
        let status = u16::try_from(status)
            .map_err(|err| VmError::HostError(format!("invalid status: {err}")))?;
        session
            .response_mut()?
            .set_status(status)
            .map_err(|err| VmError::HostError(format!("Pingora response set_status: {err}")))?;
        Ok(true)
    }

    /// Returns the live Pingora response status code.
    #[pd_host_function(name = "pingora::response::status")]
    pub(super) fn response_status_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
    ) -> VmResult<i64> {
        Ok(i64::from(session.response()?.status.as_u16()))
    }

    /// Reads a header from the live Pingora response.
    #[pd_host_function(name = "pingora::response::header")]
    pub(super) fn response_header_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
        name: &str,
    ) -> VmResult<String> {
        Ok(session
            .response()?
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string())
    }

    /// Calls Pingora ResponseHeader::insert_header on the live response.
    #[pd_host_function(name = "pingora::response::insert_header")]
    pub(super) fn response_insert_header_impl(
        mut session: HostStateMut<'_, PingoraPolicySession>,
        name: &str,
        value: &str,
    ) -> VmResult<bool> {
        ensure_script_header_allowed(name)?;
        session
            .response_mut()?
            .insert_header(name.to_string(), value.to_string())
            .map_err(|err| VmError::HostError(format!("Pingora response insert_header: {err}")))?;
        Ok(true)
    }

    /// Calls Pingora ResponseHeader::append_header on the live response.
    #[pd_host_function(name = "pingora::response::append_header")]
    pub(super) fn response_append_header_impl(
        mut session: HostStateMut<'_, PingoraPolicySession>,
        name: &str,
        value: &str,
    ) -> VmResult<bool> {
        ensure_script_header_allowed(name)?;
        session
            .response_mut()?
            .append_header(name.to_string(), value.to_string())
            .map_err(|err| VmError::HostError(format!("Pingora response append_header: {err}")))
    }

    /// Calls Pingora ResponseHeader::remove_header on the live response.
    #[pd_host_function(name = "pingora::response::remove_header")]
    pub(super) fn response_remove_header_impl(
        mut session: HostStateMut<'_, PingoraPolicySession>,
        name: &str,
    ) -> VmResult<bool> {
        ensure_script_header_allowed(name)?;
        Ok(session.response_mut()?.remove_header(name).is_some())
    }

    /// Returns the live Pingora response as a named PingoraResponse struct.
    #[pd_host_function(name = "pingora::response::info", contract = response_info_contract)]
    pub(super) fn response_info_impl(
        session: HostStateRef<'_, PingoraPolicySession>,
    ) -> VmResult<VmMap> {
        Ok(named_map(vec![(
            "status",
            vm::Value::Int(i64::from(session.response()?.status.as_u16())),
        )]))
    }

    fn response_info_contract() -> HostFunctionSchema {
        HostFunctionSchema::with_return(
            "pingora::response::info",
            vec![],
            PingoraResponse::host_type_schema(),
        )
        .with_description("Returns the live Pingora response as a named PingoraResponse struct.")
    }
}

mod policy {
    use super::*;

    /// Returns the running policy VM budget as a named PingoraPolicy struct.
    #[pd_host_function(name = "pingora::policy::info", contract = policy_info_contract)]
    pub(super) fn policy_info_impl(vm: &mut Vm) -> VmResult<VmMap> {
        let fuel = i64::try_from(vm.get_fuel().unwrap_or(0)).unwrap_or(i64::MAX);
        Ok(named_map(vec![("fuel", vm::Value::Int(fuel))]))
    }

    fn policy_info_contract() -> HostFunctionSchema {
        HostFunctionSchema::with_return(
            "pingora::policy::info",
            vec![],
            PingoraPolicy::host_type_schema(),
        )
        .with_description("Returns the running policy VM budget as a named PingoraPolicy struct.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm::{HostEffect, HostParamPassing, catalog_import_schemas};

    #[test]
    fn restricted_registry_installs_composed_pingora_modules() {
        let catalog = pingora_host_catalog();
        let mut registry = HostFunctionRegistry::restricted();
        for module in pingora_host_modules() {
            module
                .install_from_catalog(&mut registry, catalog.as_ref())
                .expect("restricted registry should accept exact pingora install");
        }
        assert!(registry.contains_name("pingora::request::method"));
        assert!(registry.contains_name("pingora::request::info"));
        assert!(registry.contains_name("pingora::upstream::info"));
        assert!(registry.contains_name("pingora::response::info"));
        assert!(registry.contains_name("pingora::policy::info"));
        assert!(!registry.contains_name("pingora::request::id"));
    }

    #[test]
    fn duplicate_module_install_rolls_back_and_preserves_generation() {
        let catalog = pingora_host_catalog();
        let mut registry = HostFunctionRegistry::empty();
        let module = pingora_request_module();
        module
            .install_from_catalog(&mut registry, catalog.as_ref())
            .expect("first install should succeed");
        let plan_before = registry
            .prepare_shared_plan(&[])
            .expect("baseline plan should build");
        let error = module
            .install_from_catalog(&mut registry, catalog.as_ref())
            .expect_err("duplicate request module must fail");
        assert!(
            error.to_string().contains("pingora::request::method"),
            "duplicate identity diagnostic should name a request function, got {error}"
        );
        let plan_after = registry
            .prepare_shared_plan(&[])
            .expect("plan after failed install should still build");
        assert!(
            std::sync::Arc::ptr_eq(&plan_before, &plan_after),
            "failed install must leave registry generation and cache identity unchanged"
        );
        assert!(registry.contains_name("pingora::request::method"));
        assert!(!registry.contains_name("pingora::response::status"));
    }

    #[test]
    fn request_mutators_declare_write_state_and_value_params() {
        let insert = request::request_insert_header_descriptor();
        assert!(
            insert
                .effects
                .iter()
                .any(|effect| matches!(effect, HostEffect::HostState(_))),
            "insert_header must declare a host-state write effect"
        );
        assert_eq!(insert.schema.params.len(), 2);
        assert_eq!(insert.schema.params[0].passing, HostParamPassing::Value);
        assert_eq!(insert.schema.params[1].passing, HostParamPassing::Value);
        assert!(
            insert
                .effects
                .iter()
                .all(|effect| effect.guest_resource().is_none()),
            "request mutators keep the live Pingora header behind host-state, not a guest resource handle"
        );
    }

    #[test]
    fn named_struct_contracts_are_catalog_identity() {
        let catalog = pingora_host_catalog();
        for (name, struct_name) in [
            ("pingora::request::info", "PingoraRequest"),
            ("pingora::upstream::info", "PingoraUpstream"),
            ("pingora::response::info", "PingoraResponse"),
            ("pingora::policy::info", "PingoraPolicy"),
        ] {
            let schemas = catalog_import_schemas(&catalog, name);
            assert_eq!(schemas.len(), 1, "{name}");
            match &schemas[0].return_type {
                HostTypeSchema::Named { name, .. } => assert_eq!(name, struct_name),
                other => panic!("{name} must return named {struct_name}, got {other:?}"),
            }
            assert!(catalog.struct_named(struct_name).is_some());
        }
    }
}
