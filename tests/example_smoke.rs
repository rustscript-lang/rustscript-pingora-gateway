use std::process::Command;

fn run_example(name: &str) -> String {
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
        .args(["run", "--quiet", "--example", name])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap_or_else(|err| panic!("{name} example should launch: {err}"));

    assert!(
        output.status.success(),
        "{name} example failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn decision_example_runs_end_to_end() {
    let stdout = run_example("decision");
    assert!(
        stdout.contains("status=403, reason=upgrade required, request_checked=true"),
        "unexpected decision example stdout:\n{stdout}"
    );
}

#[test]
fn protocols_example_runs_all_scripts() {
    let stdout = run_example("protocols");
    for label in [
        "http_proxy",
        "tls_termination",
        "websocket_proxy",
        "transport_matrix",
    ] {
        assert!(
            stdout.contains(label),
            "missing {label} in stdout:\n{stdout}"
        );
    }
}
