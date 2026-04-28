use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    pin::Pin,
    str,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{
        CONNECTION, CONTENT_TYPE, HOST, HeaderMap, HeaderName, PROXY_AUTHORIZATION, TE, TRAILER,
        TRANSFER_ENCODING, UPGRADE,
    },
    http::uri::Authority,
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, warn};

const MAX_INITIAL_HEADER_BYTES: usize = 64 * 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type HttpClient = Client<HttpConnector, Incoming>;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    allowed_domains: Arc<[String]>,
}

impl ProxyConfig {
    pub fn new<I, S>(allowed_domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let allowed_domains = allowed_domains
            .into_iter()
            .map(|domain| normalize_domain(&domain.into()))
            .filter(|domain| !domain.is_empty())
            .collect::<Vec<_>>()
            .into();

        Self { allowed_domains }
    }

    pub fn default_allowed_domains() -> Vec<String> {
        ["tidal.com", "airable.io", "qobuz.com", "spotifycdn.com"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    pub fn is_allowed_host(&self, host: &str) -> bool {
        let host = normalize_domain(host);

        self.allowed_domains
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
    }

    pub fn allowed_domains(&self) -> &[String] {
        &self.allowed_domains
    }
}

#[derive(Clone)]
pub struct ProxyServer {
    config: ProxyConfig,
    client: HttpClient,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(true);

        let client = Client::builder(TokioExecutor::new()).build(connector);

        Self { config, client }
    }

    pub async fn run(self, listen: SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(listen).await?;
        info!(
            listen = %listener.local_addr()?,
            allowed_domains = ?self.config.allowed_domains(),
            "proxy listening"
        );

        let server = Arc::new(self);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let server = Arc::clone(&server);

            tokio::spawn(async move {
                if let Err(err) = server.handle_connection(stream, peer_addr).await {
                    debug!(%peer_addr, error = %err, "connection closed with error");
                }
            });
        }
    }

    async fn handle_connection(
        self: Arc<Self>,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        let initial = match read_initial_header(&mut stream).await {
            Ok(initial) => initial,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => {
                let _ = write_plain_response(
                    &mut stream,
                    "400 Bad Request",
                    "could not read proxy request",
                )
                .await;
                return Err(err);
            }
        };

        if is_connect_request(&initial) {
            return self.handle_connect(stream, initial, peer_addr).await;
        }

        self.handle_http(stream, initial, peer_addr).await
    }

    async fn handle_connect(
        &self,
        mut client_stream: TcpStream,
        initial: Vec<u8>,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        let header_end = find_header_end(&initial)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing header end"))?;
        let header = &initial[..header_end];
        let leftover = &initial[header_end..];

        let target = match parse_connect_target(header) {
            Ok(target) => target,
            Err(err) => {
                write_plain_response(&mut client_stream, "400 Bad Request", &err).await?;
                return Ok(());
            }
        };

        if !self.config.is_allowed_host(&target.host) {
            warn!(
                %peer_addr,
                host = %target.host,
                port = target.port,
                "blocked CONNECT target"
            );
            write_plain_response(
                &mut client_stream,
                "403 Forbidden",
                "target host is not allowed by this proxy",
            )
            .await?;
            return Ok(());
        }

        let upstream_addr = format!("{}:{}", target.host, target.port);
        let mut upstream_stream = match TcpStream::connect(&upstream_addr).await {
            Ok(stream) => stream,
            Err(err) => {
                error!(
                    %peer_addr,
                    upstream = %upstream_addr,
                    error = %err,
                    "CONNECT upstream connection failed"
                );
                write_plain_response(
                    &mut client_stream,
                    "502 Bad Gateway",
                    "could not connect to target host",
                )
                .await?;
                return Ok(());
            }
        };

        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        if !leftover.is_empty() {
            upstream_stream.write_all(leftover).await?;
        }

        info!(
            %peer_addr,
            host = %target.host,
            port = target.port,
            "CONNECT tunnel established"
        );

        let started_at = Instant::now();

        match tokio::io::copy_bidirectional(&mut client_stream, &mut upstream_stream).await {
            Ok((client_to_target_bytes, target_to_client_bytes)) => {
                info!(
                    %peer_addr,
                    host = %target.host,
                    port = target.port,
                    client_to_target_bytes,
                    target_to_client_bytes,
                    duration_ms = started_at.elapsed().as_millis(),
                    "CONNECT tunnel closed"
                );
            }
            Err(err) => {
                warn!(
                    %peer_addr,
                    host = %target.host,
                    port = target.port,
                    error = %err,
                    duration_ms = started_at.elapsed().as_millis(),
                    "CONNECT tunnel closed with error"
                );
            }
        }

        Ok(())
    }

    async fn handle_http(
        self: Arc<Self>,
        stream: TcpStream,
        initial: Vec<u8>,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        let io = PrefixedIo::new(initial, stream);
        let service = service_fn(move |req| {
            let server = Arc::clone(&self);

            async move {
                let response = server.proxy_http_request(req, peer_addr).await;
                Ok::<_, Infallible>(response)
            }
        });

        hyper::server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(TokioIo::new(io), service)
            .await
            .map_err(io::Error::other)
    }

    async fn proxy_http_request(
        &self,
        mut req: Request<Incoming>,
        peer_addr: SocketAddr,
    ) -> Response<ProxyBody> {
        if req.method() == Method::CONNECT {
            return text_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "CONNECT is handled by the TCP tunnel path",
            );
        }

        let destination = match prepare_http_proxy_request(&mut req) {
            Ok(destination) => destination,
            Err(response) => return response,
        };

        if !self.config.is_allowed_host(&destination.host) {
            warn!(
                %peer_addr,
                method = %req.method(),
                uri = %req.uri(),
                host = %destination.host,
                "blocked HTTP target"
            );
            return text_response(
                StatusCode::FORBIDDEN,
                "target host is not allowed by this proxy",
            );
        }

        info!(
            %peer_addr,
            method = %req.method(),
            uri = %req.uri(),
            "proxying HTTP request"
        );

        strip_hop_by_hop_headers(req.headers_mut());

        match self.client.request(req).await {
            Ok(mut response) => {
                strip_hop_by_hop_headers(response.headers_mut());
                response.map(|body| {
                    body.map_err(|err| -> BoxError { Box::new(err) })
                        .boxed_unsync()
                })
            }
            Err(err) => {
                error!(%peer_addr, error = %err, "HTTP upstream request failed");
                text_response(StatusCode::BAD_GATEWAY, "upstream request failed")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ConnectTarget {
    host: String,
    port: u16,
}

#[derive(Debug, PartialEq, Eq)]
struct HttpDestination {
    host: String,
}

fn read_request_line(header: &[u8]) -> Result<&str, String> {
    let first_line_end = header
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| "request line is missing".to_string())?;

    let first_line = &header[..first_line_end];
    let first_line = first_line.strip_suffix(b"\r").unwrap_or(first_line);

    str::from_utf8(first_line).map_err(|_| "request line is not valid UTF-8".to_string())
}

fn parse_connect_target(header: &[u8]) -> Result<ConnectTarget, String> {
    let request_line = read_request_line(header)?;
    let mut parts = request_line.split_whitespace();

    let method = parts
        .next()
        .ok_or_else(|| "request method is missing".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "CONNECT target is missing".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "HTTP version is missing".to_string())?;

    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err("request method is not CONNECT".to_string());
    }

    if !version.starts_with("HTTP/") {
        return Err("invalid HTTP version".to_string());
    }

    parse_authority_target(target, 443)
}

fn parse_authority_target(target: &str, default_port: u16) -> Result<ConnectTarget, String> {
    if target.contains("://") {
        let uri = target
            .parse::<Uri>()
            .map_err(|err| format!("invalid CONNECT URI: {err}"))?;
        let host = uri
            .host()
            .ok_or_else(|| "CONNECT URI host is missing".to_string())?;
        let port = uri.port_u16().unwrap_or(default_port);

        return Ok(ConnectTarget {
            host: host.to_string(),
            port,
        });
    }

    let authority = target
        .parse::<Authority>()
        .map_err(|err| format!("invalid CONNECT authority: {err}"))?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(default_port);

    Ok(ConnectTarget {
        host: host.to_string(),
        port,
    })
}

fn prepare_http_proxy_request(
    req: &mut Request<Incoming>,
) -> Result<HttpDestination, Response<ProxyBody>> {
    let uri = req.uri().clone();

    let scheme = uri.scheme_str().unwrap_or("http");
    if scheme != "http" {
        return Err(text_response(
            StatusCode::BAD_REQUEST,
            "plain HTTP proxy requests must use http:// URIs; use CONNECT for HTTPS",
        ));
    }

    let host = if let Some(host) = uri.host() {
        host.to_string()
    } else {
        let host = match req
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
        {
            Some(host) => host.to_string(),
            None => {
                return Err(text_response(
                    StatusCode::BAD_REQUEST,
                    "HTTP proxy request is missing target host",
                ));
            }
        };

        let path_and_query = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let upstream_uri = format!("http://{host}{path_and_query}")
            .parse::<Uri>()
            .map_err(|_| text_response(StatusCode::BAD_REQUEST, "invalid target host"))?;
        *req.uri_mut() = upstream_uri;

        host_without_port(&host).to_string()
    };

    req.headers_mut().remove(PROXY_AUTHORIZATION);

    Ok(HttpDestination { host })
}

fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host);
    }

    host.split(':').next().unwrap_or(host)
}

async fn read_initial_header(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut chunk).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before request headers",
            ));
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);

        if find_header_end(&buffer).is_some() {
            return Ok(buffer);
        }

        if buffer.len() > MAX_INITIAL_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers exceed maximum size",
            ));
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .or_else(|| {
            buffer
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| index + 2)
        })
}

fn is_connect_request(buffer: &[u8]) -> bool {
    read_request_line(buffer)
        .ok()
        .and_then(|line| line.split_whitespace().next())
        .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_headers = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect::<Vec<_>>();

    for name in connection_headers {
        headers.remove(name);
    }

    headers.remove(CONNECTION);
    headers.remove(HeaderName::from_static("proxy-connection"));
    headers.remove(HeaderName::from_static("keep-alive"));
    headers.remove(TE);
    headers.remove(TRAILER);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
}

async fn write_plain_response(stream: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    stream.write_all(response.as_bytes()).await
}

fn text_response(status: StatusCode, body: &str) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(body.to_string()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    response
}

fn full_body(body: String) -> ProxyBody {
    Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn normalize_domain(domain: &str) -> String {
    domain
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

struct PrefixedIo {
    prefix: Vec<u8>,
    position: usize,
    stream: TcpStream,
}

impl PrefixedIo {
    fn new(prefix: Vec<u8>, stream: TcpStream) -> Self {
        Self {
            prefix,
            position: 0,
            stream,
        }
    }
}

impl AsyncRead for PrefixedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.position < this.prefix.len() {
            let remaining = &this.prefix[this.position..];
            let bytes_to_copy = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..bytes_to_copy]);
            this.position += bytes_to_copy;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for PrefixedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_exact_and_subdomains_only() {
        let config = ProxyConfig::new(ProxyConfig::default_allowed_domains());

        assert!(config.is_allowed_host("tidal.com"));
        assert!(config.is_allowed_host("api.tidal.com"));
        assert!(config.is_allowed_host("AUDIO.SPOTIFYCDN.COM"));
        assert!(!config.is_allowed_host("not-tidal.com"));
        assert!(!config.is_allowed_host("spotifycdn.com.evil.test"));
    }

    #[test]
    fn parses_connect_authority_targets() {
        let header = b"CONNECT stream.tidal.com:443 HTTP/1.1\r\nHost: stream.tidal.com:443\r\n\r\n";

        assert_eq!(
            parse_connect_target(header).unwrap(),
            ConnectTarget {
                host: "stream.tidal.com".to_string(),
                port: 443,
            }
        );
    }

    #[test]
    fn parses_connect_uri_targets() {
        assert_eq!(
            parse_authority_target("https://open.qobuz.com:8443", 443).unwrap(),
            ConnectTarget {
                host: "open.qobuz.com".to_string(),
                port: 8443,
            }
        );
    }
}
