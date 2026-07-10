use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unused_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port should bind");
    listener
        .local_addr()
        .expect("listener should have an address")
}

fn wait_for_listener(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("proxy did not listen on {addr}");
}

fn send_request(addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("client should connect to Pingora");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout should apply");
    stream
        .write_all(request.as_bytes())
        .expect("request should reach Pingora");

    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(err) => panic!("failed to read Pingora response: {err}"),
        }
    }
    String::from_utf8(response).expect("response should be UTF-8")
}

fn spawn_upstream(listener: TcpListener) -> mpsc::Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("upstream listener should become nonblocking");
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("upstream failed to accept Pingora connection: {err}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("upstream read timeout should apply");

        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream
                .read(&mut chunk)
                .expect("upstream should read request from Pingora");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        sender
            .send(String::from_utf8(request).expect("upstream request should be UTF-8"))
            .expect("test should receive observed upstream request");

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 18\r\nx-loopback-upstream: reached\r\nconnection: close\r\n\r\nreal-upstream-body",
            )
            .expect("upstream response should reach Pingora");
    });
    receiver
}

#[test]
fn pingora_accepts_a_real_client_and_forwards_to_a_real_upstream_socket() {
    let upstream_listener =
        TcpListener::bind("127.0.0.1:0").expect("loopback upstream should bind");
    let upstream_addr = upstream_listener
        .local_addr()
        .expect("upstream should have an address");
    let observed_upstream = spawn_upstream(upstream_listener);
    let proxy_addr = unused_loopback_addr();

    let child = Command::new(env!("CARGO_BIN_EXE_gateway"))
        .args([
            "--listen",
            &proxy_addr.to_string(),
            "--upstream",
            &upstream_addr.to_string(),
            "--script",
            concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/gateway_policy.rss"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Pingora gateway binary should start");
    let _gateway = ChildGuard(child);
    wait_for_listener(proxy_addr);

    let denied = send_request(
        proxy_addr,
        "GET /admin HTTP/1.1\r\nhost: gateway.test\r\nx-user-tier: free\r\nconnection: close\r\n\r\n",
    );
    assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
    assert!(
        denied
            .to_ascii_lowercase()
            .contains("x-rustscript-deny-reason: upgrade required"),
        "{denied}"
    );
    assert!(
        observed_upstream
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "denied request must not reach upstream"
    );

    let forwarded = send_request(
        proxy_addr,
        "GET /canary HTTP/1.1\r\nhost: gateway.test\r\nconnection: close\r\n\r\n",
    );
    let forwarded_lower = forwarded.to_ascii_lowercase();
    assert!(forwarded.starts_with("HTTP/1.1 200"), "{forwarded}");
    assert!(forwarded.ends_with("real-upstream-body"), "{forwarded}");
    assert!(
        forwarded_lower.contains("x-loopback-upstream: reached"),
        "{forwarded}"
    );
    assert!(
        forwarded_lower.contains("x-rustscript-policy: gateway_policy"),
        "{forwarded}"
    );
    assert!(
        forwarded_lower.contains("x-rustscript-upstream: loopback-upstream"),
        "{forwarded}"
    );

    let upstream_request = observed_upstream
        .recv_timeout(Duration::from_secs(2))
        .expect("Pingora should open an upstream socket and send the request");
    let upstream_lower = upstream_request.to_ascii_lowercase();
    assert!(upstream_request.starts_with("GET /canary HTTP/1.1"));
    assert!(
        upstream_lower.contains("x-rustscript-checked: true"),
        "{upstream_request}"
    );
    assert!(
        upstream_lower.contains(&format!("host: {upstream_addr}")),
        "{upstream_request}"
    );
}
