use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
};

use pingora::http::{RequestHeader, ResponseHeader};
pub(crate) use vm::Vm;
use vm::{
    CallOutcome, CallReturn, HostArgsFunction, Value, VmError, VmResult, VmStatus, compile_source,
};

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
        Ok(self.evaluate(request)?.response)
    }

    pub fn evaluate(&self, request: &mut RequestHeader) -> Result<GatewayEvaluation, String> {
        let runtime = GatewayRuntime::from_request(request);
        let runtime = with_gateway_runtime(runtime, || run_policy(&self.source))?;
        runtime.apply_request_mutations(request)?;
        runtime.into_evaluation()
    }
}

#[derive(Debug, Clone)]
pub struct GatewayEvaluation {
    pub response: ResponseHeader,
    pub body: String,
    pub proxy_events: Vec<String>,
}

#[derive(Debug, Clone)]
struct RequestModel {
    id: String,
    method: String,
    path: String,
    query: String,
    scheme: String,
    host: String,
    client_ip: String,
    version: String,
    port: i64,
    headers: BTreeMap<String, String>,
    inserted_headers: BTreeMap<String, String>,
    body: String,
    transport_attached: bool,
}

#[derive(Debug, Clone)]
struct ResponseModel {
    status: i64,
    headers: BTreeMap<String, Vec<String>>,
    body: String,
}

#[derive(Debug, Clone)]
struct ExchangeModel {
    method: String,
    scheme: String,
    host: String,
    port: i64,
    path: String,
    query: String,
    headers: BTreeMap<String, String>,
    body: String,
    sent: bool,
    response_status: i64,
    response_headers: BTreeMap<String, String>,
    response_body: String,
    body_cursor: usize,
    attached_stream: Option<i64>,
}

#[derive(Debug, Clone)]
struct TcpStreamModel {
    present: bool,
    phase: String,
    local_addr: String,
    peer_addr: String,
    target: String,
    read_buffer: String,
    written: String,
    eof: bool,
}

#[derive(Debug, Clone)]
struct TlsSessionModel {
    _socket: i64,
    present: bool,
    phase: String,
    alpn: String,
    sni: String,
    verify: bool,
    peer_name: String,
    peer_certificate: String,
    reused: bool,
}

#[derive(Debug, Clone)]
struct WebSocketModel {
    present: bool,
    phase: String,
    host: String,
    port: i64,
    path: String,
    headers: BTreeMap<String, String>,
    subprotocols: String,
    selected_subprotocol: String,
    text_queue: VecDeque<String>,
    binary_queue: VecDeque<String>,
    sent: Vec<String>,
    eof: bool,
}

#[derive(Debug, Clone)]
struct ProxyStreamModel {
    _kind: String,
    _source_handle: i64,
    buffer: String,
    _closed: bool,
}

#[derive(Debug, Clone)]
struct GatewayRuntime {
    request: RequestModel,
    response: ResponseModel,
    exchanges: BTreeMap<i64, ExchangeModel>,
    tcp_streams: BTreeMap<i64, TcpStreamModel>,
    tls_sessions: BTreeMap<i64, TlsSessionModel>,
    websockets: BTreeMap<i64, WebSocketModel>,
    proxy_streams: BTreeMap<i64, ProxyStreamModel>,
    next_handle: i64,
    proxy_events: Vec<String>,
}

impl GatewayRuntime {
    fn from_request(request: &RequestHeader) -> Self {
        let raw_path = String::from_utf8_lossy(request.raw_path()).into_owned();
        let (path, query) = raw_path
            .split_once('?')
            .map(|(path, query)| (path.to_string(), query.to_string()))
            .unwrap_or_else(|| (raw_path, String::new()));
        let headers = request
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (norm(name.as_str()), value.to_string()))
            })
            .collect::<BTreeMap<_, _>>();
        let host = headers
            .get("host")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let scheme = headers
            .get("x-downstream-scheme")
            .cloned()
            .unwrap_or_else(|| "http".to_string());
        let port = if scheme == "https" { 443 } else { 80 };
        let mut runtime = Self {
            request: RequestModel {
                id: "pingora-request-1".to_string(),
                method: request.method.as_str().to_string(),
                path,
                query,
                scheme,
                host,
                client_ip: "127.0.0.1".to_string(),
                version: "HTTP/1.1".to_string(),
                port,
                headers,
                inserted_headers: BTreeMap::new(),
                body: String::new(),
                transport_attached: false,
            },
            response: ResponseModel::default(),
            exchanges: BTreeMap::new(),
            tcp_streams: BTreeMap::new(),
            tls_sessions: BTreeMap::new(),
            websockets: BTreeMap::new(),
            proxy_streams: BTreeMap::new(),
            next_handle: 10,
            proxy_events: Vec::new(),
        };
        let downstream = runtime.alloc_handle();
        runtime
            .tcp_streams
            .insert(downstream, TcpStreamModel::downstream());
        runtime.proxy_streams.insert(
            downstream,
            ProxyStreamModel::new("downstream", downstream, String::new()),
        );
        let upstream = runtime.alloc_handle();
        runtime
            .tcp_streams
            .insert(upstream, TcpStreamModel::default_upstream());
        let ws_downstream = runtime.alloc_handle();
        runtime
            .websockets
            .insert(ws_downstream, WebSocketModel::downstream());
        let ws_upstream = runtime.alloc_handle();
        runtime
            .websockets
            .insert(ws_upstream, WebSocketModel::default_upstream());
        let default_exchange = runtime.alloc_handle();
        runtime
            .exchanges
            .insert(default_exchange, runtime.default_exchange());
        runtime
    }

    fn alloc_handle(&mut self) -> i64 {
        let handle = self.next_handle;
        self.next_handle += 1;
        handle
    }

    fn default_exchange(&self) -> ExchangeModel {
        let mut headers = BTreeMap::new();
        headers.insert("x-from".to_string(), "pingora-rustscript".to_string());
        ExchangeModel {
            method: self.request.method.clone(),
            scheme: self.request.scheme.clone(),
            host: self.request.host.clone(),
            port: self.request.port,
            path: self.request.path.clone(),
            query: self.request.query.clone(),
            headers,
            body: self.request.body.clone(),
            sent: false,
            response_status: 200,
            response_headers: BTreeMap::from([
                ("content-type".to_string(), "text/plain".to_string()),
                ("x-upstream".to_string(), "pingora-fixture".to_string()),
            ]),
            response_body: String::new(),
            body_cursor: 0,
            attached_stream: None,
        }
    }

    fn new_exchange(&mut self) -> i64 {
        let handle = self.alloc_handle();
        let exchange = self.default_exchange();
        self.exchanges.insert(handle, exchange);
        handle
    }

    fn default_exchange_handle(&mut self) -> i64 {
        if let Some((&handle, _)) = self.exchanges.iter().next() {
            handle
        } else {
            self.new_exchange()
        }
    }

    fn ensure_exchange_response(&mut self, handle: i64) -> VmResult<()> {
        let exchange = self.exchange_mut(handle)?;
        if !exchange.sent {
            exchange.sent = true;
            if exchange.response_body.is_empty() {
                let target = format!(
                    "{}://{}:{}{}",
                    exchange.scheme, exchange.host, exchange.port, exchange.path
                );
                exchange.response_body = if exchange.body.is_empty() {
                    format!("proxied {target}")
                } else {
                    format!("proxied {target} body={}", exchange.body)
                };
            }
        }
        Ok(())
    }

    fn exchange_mut(&mut self, handle: i64) -> VmResult<&mut ExchangeModel> {
        self.exchanges
            .get_mut(&handle)
            .ok_or_else(|| VmError::HostError(format!("unknown HTTP exchange handle: {handle}")))
    }

    fn exchange(&self, handle: i64) -> VmResult<&ExchangeModel> {
        self.exchanges
            .get(&handle)
            .ok_or_else(|| VmError::HostError(format!("unknown HTTP exchange handle: {handle}")))
    }

    fn tcp_mut(&mut self, handle: i64) -> VmResult<&mut TcpStreamModel> {
        self.tcp_streams
            .get_mut(&handle)
            .ok_or_else(|| VmError::HostError(format!("unknown TCP stream handle: {handle}")))
    }

    fn tcp(&self, handle: i64) -> VmResult<&TcpStreamModel> {
        self.tcp_streams
            .get(&handle)
            .ok_or_else(|| VmError::HostError(format!("unknown TCP stream handle: {handle}")))
    }

    fn tls_mut(&mut self, handle: i64) -> VmResult<&mut TlsSessionModel> {
        self.tls_sessions
            .get_mut(&handle)
            .ok_or_else(|| VmError::HostError(format!("unknown TLS session handle: {handle}")))
    }

    fn tls(&self, handle: i64) -> VmResult<&TlsSessionModel> {
        self.tls_sessions
            .get(&handle)
            .ok_or_else(|| VmError::HostError(format!("unknown TLS session handle: {handle}")))
    }

    fn ws_mut(&mut self, handle: i64) -> VmResult<&mut WebSocketModel> {
        self.websockets
            .get_mut(&handle)
            .ok_or_else(|| VmError::HostError(format!("unknown WebSocket handle: {handle}")))
    }

    fn ws(&self, handle: i64) -> VmResult<&WebSocketModel> {
        self.websockets
            .get(&handle)
            .ok_or_else(|| VmError::HostError(format!("unknown WebSocket handle: {handle}")))
    }

    fn apply_request_mutations(&self, request: &mut RequestHeader) -> Result<(), String> {
        for (name, value) in &self.request.inserted_headers {
            request
                .insert_header(name.clone(), value.clone())
                .map_err(|err| format!("Pingora request insert_header: {err}"))?;
        }
        Ok(())
    }

    fn into_evaluation(self) -> Result<GatewayEvaluation, String> {
        let mut response = ResponseHeader::build(self.response.status as u16, Some(16))
            .map_err(|err| format!("failed to build Pingora response: {err}"))?;
        for (name, values) in &self.response.headers {
            for value in values {
                response
                    .append_header(name.clone(), value.clone())
                    .map_err(|err| format!("Pingora response append_header: {err}"))?;
            }
        }
        Ok(GatewayEvaluation {
            response,
            body: self.response.body,
            proxy_events: self.proxy_events,
        })
    }
}

impl Default for ResponseModel {
    fn default() -> Self {
        Self {
            status: 200,
            headers: BTreeMap::new(),
            body: String::new(),
        }
    }
}

impl TcpStreamModel {
    fn new() -> Self {
        Self {
            present: true,
            phase: "new".to_string(),
            local_addr: "127.0.0.1:0".to_string(),
            peer_addr: "".to_string(),
            target: String::new(),
            read_buffer: "pingora-stream".to_string(),
            written: String::new(),
            eof: false,
        }
    }
    fn downstream() -> Self {
        Self {
            phase: "downstream".to_string(),
            peer_addr: "127.0.0.1:54321".to_string(),
            ..Self::new()
        }
    }
    fn default_upstream() -> Self {
        Self {
            phase: "default-upstream".to_string(),
            target: "127.0.0.1:80".to_string(),
            ..Self::new()
        }
    }
}

impl TlsSessionModel {
    fn new(socket: i64) -> Self {
        Self {
            _socket: socket,
            present: true,
            phase: "configured".to_string(),
            alpn: "http/1.1".to_string(),
            sni: "localhost".to_string(),
            verify: true,
            peer_name: "localhost".to_string(),
            peer_certificate: "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----"
                .to_string(),
            reused: false,
        }
    }
}

impl WebSocketModel {
    fn new() -> Self {
        Self {
            present: true,
            phase: "new".to_string(),
            host: "127.0.0.1".to_string(),
            port: 80,
            path: "/".to_string(),
            headers: BTreeMap::new(),
            subprotocols: String::new(),
            selected_subprotocol: String::new(),
            text_queue: VecDeque::new(),
            binary_queue: VecDeque::new(),
            sent: Vec::new(),
            eof: false,
        }
    }
    fn downstream() -> Self {
        Self {
            phase: "downstream-upgrade".to_string(),
            ..Self::new()
        }
    }
    fn default_upstream() -> Self {
        Self {
            phase: "default-upstream".to_string(),
            ..Self::new()
        }
    }
}

impl ProxyStreamModel {
    fn new(kind: &str, source_handle: i64, buffer: String) -> Self {
        Self {
            _kind: kind.to_string(),
            _source_handle: source_handle,
            buffer,
            _closed: false,
        }
    }
}

thread_local! {
    static GATEWAY_RUNTIME: RefCell<Option<GatewayRuntime>> = const { RefCell::new(None) };
}

struct GatewayRuntimeGuard;

impl Drop for GatewayRuntimeGuard {
    fn drop(&mut self) {}
}

fn with_gateway_runtime<T>(
    runtime: GatewayRuntime,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<GatewayRuntime, String> {
    GATEWAY_RUNTIME.with(|slot| {
        *slot.borrow_mut() = Some(runtime);
    });
    let _guard = GatewayRuntimeGuard;
    f()?;
    GATEWAY_RUNTIME.with(|slot| {
        slot.borrow_mut()
            .take()
            .ok_or_else(|| "missing Pingora gateway runtime".to_string())
    })
}

fn with_runtime<T>(f: impl FnOnce(&mut GatewayRuntime) -> VmResult<T>) -> VmResult<T> {
    GATEWAY_RUNTIME.with(|slot| {
        let mut slot = slot.borrow_mut();
        let runtime = slot
            .as_mut()
            .ok_or_else(|| VmError::HostError("missing Pingora gateway runtime".to_string()))?;
        f(runtime)
    })
}

fn run_policy(source: &str) -> Result<(), String> {
    let compiled = compile_source(source).map_err(|err| err.to_string())?;
    let mut vm = Vm::new(compiled.program);
    bind_gateway_hosts(&mut vm);
    let status = vm.run().map_err(|err| err.to_string())?;
    if status != VmStatus::Halted {
        return Err(format!("script did not halt: {status:?}"));
    }
    Ok(())
}

fn bind_gateway_hosts(vm: &mut Vm) {
    for name in GATEWAY_HOST_FUNCTIONS {
        vm.bind_args_function(*name, Box::new(DynamicGatewayHost { name }));
    }
}

struct DynamicGatewayHost {
    name: &'static str,
}

impl HostArgsFunction for DynamicGatewayHost {
    fn call(&mut self, args: &[Value]) -> VmResult<CallOutcome> {
        dispatch_host(self.name, args)
    }
}

fn dispatch_host(name: &str, args: &[Value]) -> VmResult<CallOutcome> {
    if name == "pingora::runtime::exit" {
        return Ok(CallOutcome::Halt);
    }
    with_runtime(|runtime| match name {
        "pingora::request::method" => ret(runtime.request.method.clone()),
        "pingora::request::path" => ret(runtime.request.path.clone()),
        "pingora::request::id" => ret(runtime.request.id.clone()),
        "pingora::request::query" => ret(runtime.request.query.clone()),
        "pingora::request::scheme" => ret(runtime.request.scheme.clone()),
        "pingora::request::host" => ret(runtime.request.host.clone()),
        "pingora::request::client_ip" => ret(runtime.request.client_ip.clone()),
        "pingora::request::version" => ret(runtime.request.version.clone()),
        "pingora::request::port" => ret(runtime.request.port),
        "pingora::request::path_with_query" => ret(path_with_query(
            &runtime.request.path,
            &runtime.request.query,
        )),
        "pingora::request::body" => ret(runtime.request.body.clone()),
        "pingora::request::header" => {
            let key = norm(str_arg(args, 0, "name")?);
            ret(runtime
                .request
                .headers
                .get(&key)
                .cloned()
                .unwrap_or_default())
        }
        "pingora::request::headers" => ret(join_headers(&runtime.request.headers)),
        "pingora::request::query_arg" => {
            ret(query_arg(&runtime.request.query, str_arg(args, 0, "name")?))
        }
        "pingora::request::query_args" => ret(runtime.request.query.clone()),
        "pingora::request::insert_header" => {
            let name = norm(str_arg(args, 0, "name")?);
            let value = str_arg(args, 1, "value")?.to_string();
            runtime.request.headers.insert(name.clone(), value.clone());
            runtime.request.inserted_headers.insert(name, value);
            ret(true)
        }
        "pingora::downstream::attach_http" => {
            runtime.request.transport_attached = true;
            runtime.request.scheme = "http".to_string();
            ret(true)
        }
        "pingora::response::set_status" => {
            runtime.response.status = int_arg(args, 0, "status")?;
            ret(true)
        }
        "pingora::response::status" => ret(runtime.response.status),
        "pingora::response::set_body" => {
            runtime.response.body = value_to_text(args.first(), "body")?;
            ret(true)
        }
        "pingora::response::body" => ret(runtime.response.body.clone()),
        "pingora::response::insert_header" => {
            let name = norm(str_arg(args, 0, "name")?);
            let value = str_arg(args, 1, "value")?.to_string();
            runtime.response.headers.insert(name, vec![value]);
            ret(true)
        }
        "pingora::response::append_header" => {
            let name = norm(str_arg(args, 0, "name")?);
            let value = str_arg(args, 1, "value")?.to_string();
            runtime
                .response
                .headers
                .entry(name)
                .or_default()
                .push(value);
            ret(true)
        }
        "pingora::response::remove_header" => {
            let name = norm(str_arg(args, 0, "name")?);
            runtime.response.headers.remove(&name);
            ret(true)
        }
        "pingora::response::header" => {
            let name = norm(str_arg(args, 0, "name")?);
            ret(runtime
                .response
                .headers
                .get(&name)
                .and_then(|values| values.first())
                .cloned()
                .unwrap_or_default())
        }
        "pingora::response::headers" => {
            let flat = runtime
                .response
                .headers
                .iter()
                .map(|(k, values)| format!("{k}: {}", values.join(",")))
                .collect::<Vec<_>>()
                .join("\n");
            ret(flat)
        }
        "pingora::upstream::new" => ret(runtime.new_exchange()),
        "pingora::upstream::default" => ret(runtime.default_exchange_handle()),
        "pingora::upstream::send" => {
            let handle = int_arg(args, 0, "exchange")?;
            runtime.ensure_exchange_response(handle)?;
            ret(true)
        }
        "pingora::upstream::insert_header" => set_exchange_header(runtime, args, false),
        "pingora::upstream::append_header" => set_exchange_header(runtime, args, true),
        "pingora::upstream::remove_header" => {
            let handle = int_arg(args, 0, "exchange")?;
            let name = norm(str_arg(args, 1, "name")?);
            runtime.exchange_mut(handle)?.headers.remove(&name);
            ret(true)
        }
        "pingora::upstream::set_method" => {
            set_exchange_field(runtime, args, |exchange, value| exchange.method = value)
        }
        "pingora::upstream::set_path" => {
            set_exchange_field(runtime, args, |exchange, value| exchange.path = value)
        }
        "pingora::upstream::set_query" => {
            set_exchange_field(runtime, args, |exchange, value| exchange.query = value)
        }
        "pingora::upstream::set_scheme" => {
            set_exchange_field(runtime, args, |exchange, value| exchange.scheme = value)
        }
        "pingora::upstream::set_body" => {
            set_exchange_field(runtime, args, |exchange, value| exchange.body = value)
        }
        "pingora::upstream::set_query_arg" => {
            let handle = int_arg(args, 0, "exchange")?;
            let key = str_arg(args, 1, "name")?;
            let value = str_arg(args, 2, "value")?;
            let exchange = runtime.exchange_mut(handle)?;
            exchange.query = upsert_query_arg(&exchange.query, key, value);
            ret(true)
        }
        "pingora::upstream::set_peer" => {
            let handle = int_arg(args, 0, "exchange")?;
            let host = str_arg(args, 1, "host")?.to_string();
            let port = int_arg(args, 2, "port")?;
            let exchange = runtime.exchange_mut(handle)?;
            exchange.host = host;
            exchange.port = port;
            ret(true)
        }
        "pingora::upstream::attach_tcp" | "pingora::upstream::attach_tls_plaintext" => {
            let handle = int_arg(args, 0, "exchange")?;
            let stream = int_arg(args, 1, "stream")?;
            runtime.exchange_mut(handle)?.attached_stream = Some(stream);
            ret(true)
        }
        "pingora::upstream::status" => {
            let handle = int_arg(args, 0, "exchange")?;
            runtime.ensure_exchange_response(handle)?;
            ret(runtime.exchange(handle)?.response_status)
        }
        "pingora::upstream::header" => {
            let handle = int_arg(args, 0, "exchange")?;
            let key = norm(str_arg(args, 1, "name")?);
            runtime.ensure_exchange_response(handle)?;
            ret(runtime
                .exchange(handle)?
                .response_headers
                .get(&key)
                .cloned()
                .unwrap_or_default())
        }
        "pingora::upstream::headers" => {
            let handle = int_arg(args, 0, "exchange")?;
            runtime.ensure_exchange_response(handle)?;
            ret(join_headers(&runtime.exchange(handle)?.response_headers))
        }
        "pingora::upstream::body" => {
            let handle = int_arg(args, 0, "exchange")?;
            runtime.ensure_exchange_response(handle)?;
            ret(runtime.exchange(handle)?.response_body.clone())
        }
        "pingora::upstream::version" => ret("HTTP/1.1".to_string()),
        "pingora::upstream::body_next_chunk" => {
            let handle = int_arg(args, 0, "exchange")?;
            let size = int_arg(args, 1, "size")?.max(1) as usize;
            runtime.ensure_exchange_response(handle)?;
            let exchange = runtime.exchange_mut(handle)?;
            let remaining = &exchange.response_body[exchange.body_cursor..];
            let end = remaining
                .char_indices()
                .map(|(idx, _)| idx)
                .chain(std::iter::once(remaining.len()))
                .nth(size)
                .unwrap_or(remaining.len());
            let chunk = remaining[..end].to_string();
            exchange.body_cursor += end;
            ret(chunk)
        }
        "pingora::upstream::body_eof" => {
            let handle = int_arg(args, 0, "exchange")?;
            runtime.ensure_exchange_response(handle)?;
            let exchange = runtime.exchange(handle)?;
            ret(exchange.body_cursor >= exchange.response_body.len())
        }
        "pingora::limits::allow" => {
            let key = str_arg(args, 0, "key").unwrap_or("");
            ret(!key.contains("deny") && !key.contains("block"))
        }
        "pingora::runtime::sleep" => ret(true),
        "pingora::tcp::downstream" => ret(10),
        "pingora::tcp::default_upstream" => ret(11),
        "pingora::tcp::new" => {
            let handle = runtime.alloc_handle();
            runtime.tcp_streams.insert(handle, TcpStreamModel::new());
            ret(handle)
        }
        "pingora::tcp::is_present" => ret(runtime
            .tcp(int_arg(args, 0, "stream")?)
            .map(|s| s.present)
            .unwrap_or(false)),
        "pingora::tcp::bind" => {
            let handle = int_arg(args, 0, "stream")?;
            let addr = str_arg(args, 1, "addr")?.to_string();
            runtime.tcp_mut(handle)?.local_addr = addr;
            ret(true)
        }
        "pingora::tcp::set_peer" => {
            let handle = int_arg(args, 0, "stream")?;
            let host = str_arg(args, 1, "host")?;
            let port = int_arg(args, 2, "port")?;
            runtime.tcp_mut(handle)?.target = format!("{host}:{port}");
            ret(true)
        }
        "pingora::tcp::connect" => {
            let stream = runtime.tcp_mut(int_arg(args, 0, "stream")?)?;
            stream.phase = "connected".to_string();
            stream.peer_addr = stream.target.clone();
            ret(true)
        }
        "pingora::tcp::phase" => ret(runtime.tcp(int_arg(args, 0, "stream")?)?.phase.clone()),
        "pingora::tcp::local_addr" => {
            ret(runtime.tcp(int_arg(args, 0, "stream")?)?.local_addr.clone())
        }
        "pingora::tcp::peer_addr" => {
            ret(runtime.tcp(int_arg(args, 0, "stream")?)?.peer_addr.clone())
        }
        "pingora::tcp::read" => {
            let handle = int_arg(args, 0, "stream")?;
            let size = int_arg(args, 1, "size")?.max(1) as usize;
            let stream = runtime.tcp_mut(handle)?;
            let take = stream.read_buffer.chars().take(size).collect::<String>();
            stream.read_buffer = stream
                .read_buffer
                .chars()
                .skip(take.chars().count())
                .collect();
            if stream.read_buffer.is_empty() {
                stream.eof = true;
            }
            ret(take)
        }
        "pingora::tcp::peek" => {
            let handle = int_arg(args, 0, "stream")?;
            let size = int_arg(args, 1, "size")?.max(1) as usize;
            ret(runtime
                .tcp(handle)?
                .read_buffer
                .chars()
                .take(size)
                .collect::<String>())
        }
        "pingora::tcp::write" => {
            let handle = int_arg(args, 0, "stream")?;
            let payload = value_to_text(args.get(1), "payload")?;
            runtime.tcp_mut(handle)?.written.push_str(&payload);
            ret(payload.len() as i64)
        }
        "pingora::tcp::eof" => ret(runtime.tcp(int_arg(args, 0, "stream")?)?.eof),
        "pingora::tcp::close" => {
            let stream = runtime.tcp_mut(int_arg(args, 0, "stream")?)?;
            stream.phase = "closed".to_string();
            stream.eof = true;
            ret(true)
        }
        "pingora::tls::accept" => {
            let socket = int_arg(args, 0, "socket")?;
            let handle = runtime.alloc_handle();
            runtime
                .tls_sessions
                .insert(handle, TlsSessionModel::new(socket));
            ret(handle)
        }
        "pingora::tls::is_present" => ret(runtime
            .tls(int_arg(args, 0, "session")?)
            .map(|s| s.present)
            .unwrap_or(false)),
        "pingora::tls::handshake" => {
            let session = runtime.tls_mut(int_arg(args, 0, "session")?)?;
            session.phase = "handshaked".to_string();
            session.peer_name = session.sni.clone();
            ret(true)
        }
        "pingora::tls::set_alpn" => set_tls_field(runtime, args, |s, v| s.alpn = v),
        "pingora::tls::set_sni" => set_tls_field(runtime, args, |s, v| s.sni = v),
        "pingora::tls::set_verify" | "pingora::tls::set_verify_hostname" => {
            let session = runtime.tls_mut(int_arg(args, 0, "session")?)?;
            session.verify = bool_arg(args, 1, "enabled")?;
            ret(true)
        }
        "pingora::tls::set_trusted_certificate"
        | "pingora::tls::set_client_certificate"
        | "pingora::tls::set_client_private_key"
        | "pingora::tls::set_server_certificate"
        | "pingora::tls::set_server_private_key"
        | "pingora::tls::set_min_version"
        | "pingora::tls::set_max_version" => ret(true),
        "pingora::tls::peer_name" => {
            ret(runtime.tls(int_arg(args, 0, "session")?)?.peer_name.clone())
        }
        "pingora::tls::alpn" => ret(runtime.tls(int_arg(args, 0, "session")?)?.alpn.clone()),
        "pingora::tls::phase" => ret(runtime.tls(int_arg(args, 0, "session")?)?.phase.clone()),
        "pingora::tls::peer_certificate" => ret(runtime
            .tls(int_arg(args, 0, "session")?)?
            .peer_certificate
            .clone()),
        "pingora::tls::is_reused" => ret(runtime.tls(int_arg(args, 0, "session")?)?.reused),
        "pingora::websocket::new" => {
            let handle = runtime.alloc_handle();
            runtime.websockets.insert(handle, WebSocketModel::new());
            ret(handle)
        }
        "pingora::websocket::downstream" => ret(12),
        "pingora::websocket::default_upstream" => ret(13),
        "pingora::websocket::is_present" => ret(runtime
            .ws(int_arg(args, 0, "connection")?)
            .map(|ws| ws.present)
            .unwrap_or(false)),
        "pingora::websocket::set_peer" => {
            let handle = int_arg(args, 0, "connection")?;
            let host = str_arg(args, 1, "host")?.to_string();
            let port = int_arg(args, 2, "port")?;
            let ws = runtime.ws_mut(handle)?;
            ws.host = host;
            ws.port = port;
            ret(true)
        }
        "pingora::websocket::set_path" => set_ws_field(runtime, args, |ws, value| ws.path = value),
        "pingora::websocket::set_header" => {
            let handle = int_arg(args, 0, "connection")?;
            let name = norm(str_arg(args, 1, "name")?);
            let value = str_arg(args, 2, "value")?.to_string();
            runtime.ws_mut(handle)?.headers.insert(name, value);
            ret(true)
        }
        "pingora::websocket::set_subprotocols" => {
            set_ws_field(runtime, args, |ws, value| ws.subprotocols = value)
        }
        "pingora::websocket::connect" => {
            let ws = runtime.ws_mut(int_arg(args, 0, "connection")?)?;
            ws.phase = "connected".to_string();
            ws.selected_subprotocol = ws
                .subprotocols
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            ret(true)
        }
        "pingora::websocket::phase" => {
            ret(runtime.ws(int_arg(args, 0, "connection")?)?.phase.clone())
        }
        "pingora::websocket::subprotocol" => ret(runtime
            .ws(int_arg(args, 0, "connection")?)?
            .selected_subprotocol
            .clone()),
        "pingora::websocket::send_text" => {
            let handle = int_arg(args, 0, "connection")?;
            let payload = str_arg(args, 1, "payload")?.to_string();
            let ws = runtime.ws_mut(handle)?;
            ws.sent.push(payload.clone());
            ws.text_queue.push_back(payload);
            ret(true)
        }
        "pingora::websocket::read_text" => ret(runtime
            .ws_mut(int_arg(args, 0, "connection")?)?
            .text_queue
            .pop_front()
            .unwrap_or_default()),
        "pingora::websocket::send_binary_base64" | "pingora::websocket::send_binary" => {
            let handle = int_arg(args, 0, "connection")?;
            let payload = value_to_text(args.get(1), "payload")?;
            runtime.ws_mut(handle)?.binary_queue.push_back(payload);
            ret(true)
        }
        "pingora::websocket::read_binary_base64" | "pingora::websocket::read_binary" => {
            ret(runtime
                .ws_mut(int_arg(args, 0, "connection")?)?
                .binary_queue
                .pop_front()
                .unwrap_or_default())
        }
        "pingora::websocket::eof" => ret(runtime.ws(int_arg(args, 0, "connection")?)?.eof),
        "pingora::websocket::close" => {
            let ws = runtime.ws_mut(int_arg(args, 0, "connection")?)?;
            ws.phase = "closed".to_string();
            ws.eof = true;
            ret(true)
        }
        "pingora::proxy::downstream_stream" => ret(10),
        "pingora::proxy::upstream_stream" => {
            let exchange = int_arg(args, 0, "exchange")?;
            runtime.ensure_exchange_response(exchange)?;
            let handle = runtime.alloc_handle();
            let body = runtime.exchange(exchange)?.response_body.clone();
            runtime
                .proxy_streams
                .insert(handle, ProxyStreamModel::new("exchange", exchange, body));
            ret(handle)
        }
        "pingora::proxy::tcp_stream" => {
            let tcp = int_arg(args, 0, "stream")?;
            let handle = runtime.alloc_handle();
            runtime.proxy_streams.insert(
                handle,
                ProxyStreamModel::new("tcp", tcp, runtime.tcp(tcp)?.read_buffer.clone()),
            );
            ret(handle)
        }
        "pingora::proxy::tls_plaintext_stream" => {
            let tls = int_arg(args, 0, "session")?;
            let handle = runtime.alloc_handle();
            runtime.proxy_streams.insert(
                handle,
                ProxyStreamModel::new(
                    "tls-plaintext",
                    tls,
                    format!("tls:{}", runtime.tls(tls)?.alpn),
                ),
            );
            ret(handle)
        }
        "pingora::proxy::websocket_binary_stream" => {
            let ws = int_arg(args, 0, "connection")?;
            let handle = runtime.alloc_handle();
            runtime.proxy_streams.insert(
                handle,
                ProxyStreamModel::new("websocket-binary", ws, String::new()),
            );
            ret(handle)
        }
        "pingora::proxy::pipe"
        | "pingora::proxy::bridge"
        | "pingora::proxy::forward"
        | "pingora::proxy::forward_native" => {
            let downstream = int_arg(args, 0, "downstream")?;
            let upstream = int_arg(args, 1, "upstream")?;
            let buffer = runtime
                .proxy_streams
                .get(&upstream)
                .map(|s| s.buffer.clone())
                .unwrap_or_default();
            runtime
                .proxy_events
                .push(format!("{name}:{downstream}->{upstream}:{buffer}"));
            if let Some(stream) = runtime.proxy_streams.get_mut(&downstream) {
                stream.buffer.push_str(&buffer);
            }
            ret("proxied".to_string())
        }
        _ => Err(VmError::HostError(format!(
            "unimplemented Pingora gateway host: {name}"
        ))),
    })
}

fn ret<T: IntoVmValue>(value: T) -> VmResult<CallOutcome> {
    Ok(CallOutcome::Return(CallReturn::one(value.into_vm_value())))
}

trait IntoVmValue {
    fn into_vm_value(self) -> Value;
}

impl IntoVmValue for String {
    fn into_vm_value(self) -> Value {
        Value::string(self)
    }
}
impl IntoVmValue for &str {
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

fn str_arg<'a>(args: &'a [Value], index: usize, label: &str) -> VmResult<&'a str> {
    match args.get(index) {
        Some(Value::String(text)) => Ok(text.as_str()),
        Some(_) => Err(VmError::TypeMismatch("string")),
        None => Err(VmError::HostError(format!("missing argument: {label}"))),
    }
}

fn int_arg(args: &[Value], index: usize, label: &str) -> VmResult<i64> {
    match args.get(index) {
        Some(Value::Int(value)) => Ok(*value),
        Some(_) => Err(VmError::TypeMismatch("int")),
        None => Err(VmError::HostError(format!("missing argument: {label}"))),
    }
}

fn bool_arg(args: &[Value], index: usize, label: &str) -> VmResult<bool> {
    match args.get(index) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(VmError::TypeMismatch("bool")),
        None => Err(VmError::HostError(format!("missing argument: {label}"))),
    }
}

fn value_to_text(value: Option<&Value>, label: &str) -> VmResult<String> {
    match value {
        Some(Value::String(text)) => Ok(text.to_string()),
        Some(Value::Int(value)) => Ok(value.to_string()),
        Some(Value::Float(value)) => Ok(value.to_string()),
        Some(Value::Bool(value)) => Ok(value.to_string()),
        Some(Value::Bytes(bytes)) => Ok(String::from_utf8_lossy(bytes.as_ref()).into_owned()),
        Some(Value::Null) => Ok(String::new()),
        Some(_) => Err(VmError::TypeMismatch("scalar")),
        None => Err(VmError::HostError(format!("missing argument: {label}"))),
    }
}

fn norm(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn join_headers(headers: &BTreeMap<String, String>) -> String {
    headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn path_with_query(path: &str, query: &str) -> String {
    if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    }
}

fn query_arg(query: &str, key: &str) -> String {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(k, v)| (k == key).then(|| v.to_string()))
        .unwrap_or_default()
}

fn upsert_query_arg(query: &str, key: &str, value: &str) -> String {
    let mut pairs = query
        .split('&')
        .filter(|part| !part.is_empty())
        .filter_map(|pair| {
            pair.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect::<Vec<_>>();
    if let Some((_, existing)) = pairs.iter_mut().find(|(k, _)| k == key) {
        *existing = value.to_string();
    } else {
        pairs.push((key.to_string(), value.to_string()));
    }
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn set_exchange_header(
    runtime: &mut GatewayRuntime,
    args: &[Value],
    append: bool,
) -> VmResult<CallOutcome> {
    let handle = int_arg(args, 0, "exchange")?;
    let name = norm(str_arg(args, 1, "name")?);
    let value = str_arg(args, 2, "value")?.to_string();
    let exchange = runtime.exchange_mut(handle)?;
    if append {
        exchange
            .headers
            .entry(name)
            .and_modify(|old| old.push_str(&format!(",{value}")))
            .or_insert(value);
    } else {
        exchange.headers.insert(name, value);
    }
    ret(true)
}

fn set_exchange_field(
    runtime: &mut GatewayRuntime,
    args: &[Value],
    update: impl FnOnce(&mut ExchangeModel, String),
) -> VmResult<CallOutcome> {
    let handle = int_arg(args, 0, "exchange")?;
    let value = str_arg(args, 1, "value")?.to_string();
    update(runtime.exchange_mut(handle)?, value);
    ret(true)
}

fn set_tls_field(
    runtime: &mut GatewayRuntime,
    args: &[Value],
    update: impl FnOnce(&mut TlsSessionModel, String),
) -> VmResult<CallOutcome> {
    let handle = int_arg(args, 0, "session")?;
    let value = str_arg(args, 1, "value")?.to_string();
    update(runtime.tls_mut(handle)?, value);
    ret(true)
}

fn set_ws_field(
    runtime: &mut GatewayRuntime,
    args: &[Value],
    update: impl FnOnce(&mut WebSocketModel, String),
) -> VmResult<CallOutcome> {
    let handle = int_arg(args, 0, "connection")?;
    let value = str_arg(args, 1, "value")?.to_string();
    update(runtime.ws_mut(handle)?, value);
    ret(true)
}

const GATEWAY_HOST_FUNCTIONS: &[&str] = &[
    "pingora::runtime::exit",
    "pingora::request::method",
    "pingora::request::path",
    "pingora::request::id",
    "pingora::request::query",
    "pingora::request::scheme",
    "pingora::request::host",
    "pingora::request::client_ip",
    "pingora::request::version",
    "pingora::request::port",
    "pingora::request::path_with_query",
    "pingora::request::body",
    "pingora::request::header",
    "pingora::request::headers",
    "pingora::request::query_arg",
    "pingora::request::query_args",
    "pingora::request::insert_header",
    "pingora::downstream::attach_http",
    "pingora::response::set_status",
    "pingora::response::status",
    "pingora::response::set_body",
    "pingora::response::body",
    "pingora::response::insert_header",
    "pingora::response::append_header",
    "pingora::response::remove_header",
    "pingora::response::header",
    "pingora::response::headers",
    "pingora::upstream::new",
    "pingora::upstream::default",
    "pingora::upstream::send",
    "pingora::upstream::insert_header",
    "pingora::upstream::append_header",
    "pingora::upstream::remove_header",
    "pingora::upstream::set_method",
    "pingora::upstream::set_path",
    "pingora::upstream::set_query",
    "pingora::upstream::set_scheme",
    "pingora::upstream::set_body",
    "pingora::upstream::set_query_arg",
    "pingora::upstream::set_peer",
    "pingora::upstream::attach_tcp",
    "pingora::upstream::attach_tls_plaintext",
    "pingora::upstream::status",
    "pingora::upstream::header",
    "pingora::upstream::headers",
    "pingora::upstream::body",
    "pingora::upstream::version",
    "pingora::upstream::body_next_chunk",
    "pingora::upstream::body_eof",
    "pingora::limits::allow",
    "pingora::runtime::sleep",
    "pingora::tcp::downstream",
    "pingora::tcp::default_upstream",
    "pingora::tcp::new",
    "pingora::tcp::is_present",
    "pingora::tcp::bind",
    "pingora::tcp::set_peer",
    "pingora::tcp::connect",
    "pingora::tcp::phase",
    "pingora::tcp::local_addr",
    "pingora::tcp::peer_addr",
    "pingora::tcp::read",
    "pingora::tcp::peek",
    "pingora::tcp::write",
    "pingora::tcp::eof",
    "pingora::tcp::close",
    "pingora::tls::accept",
    "pingora::tls::is_present",
    "pingora::tls::handshake",
    "pingora::tls::set_alpn",
    "pingora::tls::set_sni",
    "pingora::tls::set_verify",
    "pingora::tls::set_verify_hostname",
    "pingora::tls::set_trusted_certificate",
    "pingora::tls::set_client_certificate",
    "pingora::tls::set_client_private_key",
    "pingora::tls::set_server_certificate",
    "pingora::tls::set_server_private_key",
    "pingora::tls::set_min_version",
    "pingora::tls::set_max_version",
    "pingora::tls::peer_name",
    "pingora::tls::alpn",
    "pingora::tls::phase",
    "pingora::tls::peer_certificate",
    "pingora::tls::is_reused",
    "pingora::websocket::new",
    "pingora::websocket::downstream",
    "pingora::websocket::default_upstream",
    "pingora::websocket::is_present",
    "pingora::websocket::set_peer",
    "pingora::websocket::set_path",
    "pingora::websocket::set_header",
    "pingora::websocket::set_subprotocols",
    "pingora::websocket::connect",
    "pingora::websocket::phase",
    "pingora::websocket::subprotocol",
    "pingora::websocket::send_text",
    "pingora::websocket::read_text",
    "pingora::websocket::send_binary_base64",
    "pingora::websocket::send_binary",
    "pingora::websocket::read_binary_base64",
    "pingora::websocket::read_binary",
    "pingora::websocket::eof",
    "pingora::websocket::close",
    "pingora::proxy::downstream_stream",
    "pingora::proxy::upstream_stream",
    "pingora::proxy::tcp_stream",
    "pingora::proxy::tls_plaintext_stream",
    "pingora::proxy::websocket_binary_stream",
    "pingora::proxy::pipe",
    "pingora::proxy::bridge",
    "pingora::proxy::forward",
    "pingora::proxy::forward_native",
];
