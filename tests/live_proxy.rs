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

#[derive(Debug)]
enum UpstreamEvent {
    Accepted,
    Request(String),
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

fn connect_client(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("client should connect to Pingora");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout should apply");
    stream
}

fn write_request(stream: &mut TcpStream, request: &str) {
    stream
        .write_all(request.as_bytes())
        .expect("request should reach Pingora");
}

fn read_response_headers(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    while !response.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream
            .read(&mut chunk)
            .expect("Pingora should return response headers");
        assert!(
            read > 0,
            "Pingora closed before completing response headers"
        );
        response.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(response).expect("response headers should be UTF-8")
}

fn read_response_to_close(stream: &mut TcpStream) -> String {
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

fn spawn_upstream(listener: TcpListener) -> mpsc::Receiver<UpstreamEvent> {
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
        sender
            .send(UpstreamEvent::Accepted)
            .expect("test should receive upstream accept event");
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
            .send(UpstreamEvent::Request(
                String::from_utf8(request).expect("upstream request should be UTF-8"),
            ))
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
    let upstream_events = spawn_upstream(upstream_listener);
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

    let mut downstream = connect_client(proxy_addr);
    write_request(
        &mut downstream,
        "GET /admin HTTP/1.1\r\nhost: gateway.test\r\nx-user-tier: free\r\nconnection: keep-alive\r\n\r\n",
    );
    let denied = read_response_headers(&mut downstream);
    let denied_lower = denied.to_ascii_lowercase();
    assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
    assert!(
        denied_lower.contains("x-rustscript-deny-reason: upgrade required"),
        "{denied}"
    );
    assert!(denied_lower.contains("content-length: 0"), "{denied}");
    assert!(
        upstream_events
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "denied request must not establish an upstream connection"
    );

    write_request(
        &mut downstream,
        "GET /canary?old=1 HTTP/1.1\r\nhost: gateway.test\r\nx-rustscript-rewrite: true\r\nx-remove-me: temporary\r\nconnection: close\r\n\r\n",
    );
    let forwarded = read_response_to_close(&mut downstream);
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
        forwarded_lower.contains("x-rustscript-policy: rewritten"),
        "{forwarded}"
    );
    assert!(
        forwarded_lower.contains("x-original-target: /canary?old=1"),
        "{forwarded}"
    );
    assert!(
        !forwarded_lower.contains("x-remove-response:"),
        "{forwarded}"
    );
    assert!(
        forwarded_lower.contains("x-rustscript-upstream: loopback-upstream"),
        "{forwarded}"
    );

    assert!(matches!(
        upstream_events
            .recv_timeout(Duration::from_secs(2))
            .expect("Pingora should establish an upstream connection"),
        UpstreamEvent::Accepted
    ));
    let UpstreamEvent::Request(upstream_request) = upstream_events
        .recv_timeout(Duration::from_secs(2))
        .expect("Pingora should send an upstream request")
    else {
        panic!("expected upstream request bytes");
    };
    let upstream_lower = upstream_request.to_ascii_lowercase();
    assert!(
        upstream_request.starts_with("POST /rewritten?source=rustscript HTTP/1.1"),
        "{upstream_request}"
    );
    assert!(
        upstream_lower.contains("x-rustscript-checked: true"),
        "{upstream_request}"
    );
    assert!(
        upstream_lower.contains("x-original-query: old=1"),
        "{upstream_request}"
    );
    assert_eq!(
        upstream_lower.matches("x-request-value:").count(),
        2,
        "{upstream_request}"
    );
    assert!(
        !upstream_lower.contains("x-remove-me:"),
        "{upstream_request}"
    );
    assert!(
        upstream_lower.contains(&format!("host: {upstream_addr}")),
        "{upstream_request}"
    );
}
