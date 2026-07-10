use std::{env, fs, net::SocketAddr, process};

use pingora::{proxy::http_proxy_service, server::Server};
use rustscript_pingora_gateway_policy::{ScriptedGatewayPolicy, ScriptedProxy};

fn usage() -> ! {
    eprintln!("usage: gateway --upstream HOST:PORT [--listen HOST:PORT] [--script PATH]");
    process::exit(2);
}

fn main() {
    let mut listen = "127.0.0.1:6191".to_string();
    let mut upstream = None;
    let mut script = "scripts/gateway_policy.rss".to_string();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        let value = args.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--listen" => listen = value,
            "--upstream" => upstream = Some(value),
            "--script" => script = value,
            _ => usage(),
        }
    }

    let upstream: SocketAddr = upstream
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|err| {
            eprintln!("invalid upstream address: {err}");
            process::exit(2);
        });
    let source = fs::read_to_string(&script).unwrap_or_else(|err| {
        eprintln!("failed to read {script}: {err}");
        process::exit(2);
    });
    let policy = ScriptedGatewayPolicy::from_source(source).unwrap_or_else(|err| {
        eprintln!("failed to compile {script}: {err}");
        process::exit(2);
    });

    let mut server = Server::new(None).expect("Pingora server configuration should initialize");
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, ScriptedProxy::new(policy, upstream));
    proxy.add_tcp(&listen);
    server.add_service(proxy);

    println!("RustScript Pingora proxy listening on {listen}, forwarding to {upstream}");
    server.run_forever();
}
