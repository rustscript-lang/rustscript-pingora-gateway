use std::fs;
use std::path::{Path, PathBuf};

use pretty_assertions::assert_eq;
use rustscript_pingora_gateway::{
    ScriptedGatewayPolicy, pingora_host_catalog, pingora_production_modules,
};
use vm::{HostTypeSchema, catalog_import_schemas};

const PINGORA_CATALOG_FINGERPRINT: &str = "acce09bcf50364cc";

const PRODUCTION_FUNCTION_NAMES: &[&str] = &[
    "pingora::request::method",
    "pingora::request::path",
    "pingora::request::query",
    "pingora::request::uri",
    "pingora::request::version",
    "pingora::request::header",
    "pingora::request::insert_header",
    "pingora::request::append_header",
    "pingora::request::remove_header",
    "pingora::request::set_method",
    "pingora::request::set_uri",
    "pingora::request::info",
    "pingora::upstream::info",
    "pingora::response::set_status",
    "pingora::response::status",
    "pingora::response::header",
    "pingora::response::insert_header",
    "pingora::response::append_header",
    "pingora::response::remove_header",
    "pingora::response::info",
    "pingora::policy::info",
];

const NAMED_STRUCTS: &[&str] = &[
    "PingoraRequest",
    "PingoraUpstream",
    "PingoraResponse",
    "PingoraPolicy",
];

const FORBIDDEN_AUTHORITY: &[&str] = &[
    "bind_static_args_function",
    "bind_static_function",
    "HostApiBuilder",
    "register_catalog_static",
    "GATEWAY_CONTEXT",
    "thread_local!",
];

fn manifest_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display())) {
        let path = entry.expect("readable entry").path();
        if fs::metadata(&path).expect("source metadata").is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn production_sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rs(&manifest_root().join("src"), &mut files);
    files.sort();
    files
}

#[test]
fn composed_catalog_fingerprint_is_golden() {
    let catalog = pingora_host_catalog();
    assert_eq!(
        catalog.fingerprint().to_string(),
        PINGORA_CATALOG_FINGERPRINT
    );
}

#[test]
fn composition_owns_every_production_host_and_named_struct() {
    let catalog = pingora_host_catalog();
    let names: Vec<&str> = catalog
        .functions()
        .iter()
        .map(|function| function.name.as_str())
        .collect();
    assert_eq!(names, PRODUCTION_FUNCTION_NAMES);
    assert_eq!(pingora_production_modules().len(), 4);
    assert_eq!(
        pingora_production_modules()
            .iter()
            .map(|module| module.name)
            .collect::<Vec<_>>(),
        [
            "pingora.request",
            "pingora.upstream",
            "pingora.response",
            "pingora.policy"
        ]
    );
    for name in NAMED_STRUCTS {
        assert!(
            catalog.struct_named(name).is_some(),
            "missing named struct {name}"
        );
    }
    for function in catalog.functions() {
        assert!(
            !matches!(
                function.return_type,
                HostTypeSchema::Map(_) | HostTypeSchema::Unknown
            ),
            "{} must not return Map/Unknown",
            function.name
        );
        for param in &function.params {
            assert!(
                !matches!(param.ty, HostTypeSchema::Map(_) | HostTypeSchema::Unknown),
                "{} param {} must not be Map/Unknown",
                function.name,
                param.name
            );
        }
    }
}

#[test]
fn production_sources_have_no_parallel_registration_authority() {
    for path in production_sources() {
        let source = fs::read_to_string(&path).expect("read source");
        let production = if path.ends_with("host.rs") {
            source
                .split("#[cfg(test)]")
                .next()
                .expect("production host.rs")
                .to_string()
        } else {
            source
        };
        for token in FORBIDDEN_AUTHORITY {
            assert!(
                !production.contains(token),
                "{} still contains parallel authority token {token}",
                path.display()
            );
        }
        if path.ends_with("host.rs") {
            assert!(
                production.contains("HostModuleDescriptor"),
                "host.rs must compose HostModuleDescriptor"
            );
        }
    }
}

#[test]
fn every_bundled_rss_policy_compiles_through_the_production_catalog() {
    let scripts = manifest_root().join("scripts");
    let mut compiled = 0usize;
    for entry in fs::read_dir(&scripts).expect("scripts directory") {
        let path = entry.expect("script entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rss") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read rss");
        ScriptedGatewayPolicy::from_source(source)
            .unwrap_or_else(|err| panic!("{} should compile: {err}", path.display()));
        compiled += 1;
    }
    assert!(compiled > 0, "expected bundled RSS policies");
}

#[test]
fn named_struct_info_hosts_round_trip_live_pingora_values() {
    let policy = ScriptedGatewayPolicy::from_source(
        r#"
            use pingora;
            let request = pingora::request::info();
            let upstream = pingora::upstream::info();
            let response = pingora::response::info();
            let policy = pingora::policy::info();
            pingora::response::insert_header("x-request-method", request.method);
            pingora::response::insert_header("x-request-path", request.path);
            pingora::response::insert_header("x-upstream-address", upstream.address);
            if response.status == 200 && policy.fuel > 0 {
                pingora::response::insert_header("x-named-struct", "ok");
            }
        "#,
    )
    .expect("named-struct policy should compile");
    let mut request =
        pingora::http::RequestHeader::build("GET", b"/named", None).expect("request should build");
    let response = policy
        .evaluate_request(&mut request)
        .expect("named-struct policy should evaluate");
    assert_eq!(
        response
            .headers
            .get("x-request-method")
            .expect("method")
            .to_str()
            .unwrap(),
        "GET"
    );
    assert_eq!(
        response
            .headers
            .get("x-request-path")
            .expect("path")
            .to_str()
            .unwrap(),
        "/named"
    );
    assert_eq!(
        response
            .headers
            .get("x-named-struct")
            .expect("named-struct round trip")
            .to_str()
            .unwrap(),
        "ok"
    );
}

#[test]
fn catalog_import_schemas_carry_composed_fingerprint() {
    let catalog = pingora_host_catalog();
    let fingerprint = catalog.fingerprint();
    for name in PRODUCTION_FUNCTION_NAMES {
        let schemas = catalog_import_schemas(&catalog, name);
        assert_eq!(schemas.len(), 1, "{name}");
        assert_eq!(schemas[0].fingerprint, fingerprint);
    }
}
