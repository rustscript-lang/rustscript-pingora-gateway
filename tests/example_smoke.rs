use std::process::Command;

#[test]
fn decision_example_runs_end_to_end() {
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
        .args(["run", "--quiet", "--example", "decision"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("decision example should launch");

    assert!(
        output.status.success(),
        "decision example failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("status=403, reason=upgrade required, request_checked=true"),
        "unexpected decision example stdout:\n{stdout}"
    );
}
