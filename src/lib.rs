//! The tunnel agent's request engine.
//!
//! [`serve`] runs the gateway/thin-client end of a tunnel: it accepts the
//! request streams the relay opens and, for each, reconstructs the original
//! `http::Request`, stamps the **relay-attested** origin onto it, and drives
//! it through the caller's own `axum::Router` with `oneshot` — so the request
//! traverses the exact same identity / policy / PRMD / rate-limit / SSE path
//! it would over a real listener, with **no local TCP bind**. The response,
//! including a streaming SSE body, is chunked back down the same stream.
//!
//! Injecting the attested [`ConnectInfo`] is security-critical, not cosmetic:
//! the gateway's per-IP anonymous rate limiter reads the peer address from it
//! and *fails open* (skips limiting) when it is absent. The relay attests the
//! true client IP out-of-band; the gateway must be configured to trust the
//! tunnel origin (`server.trust_proxy_ip`) so this address — never a
//! client-supplied header — drives attribution.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use http::{HeaderName, HeaderValue, Method, Request};
use http_body_util::BodyExt;

/// Upper bound on a buffered tunnelled request body.
///
/// Matches the gateway transport's own default request-body limit, so a
/// request arriving over the tunnel is held to the same ceiling as one
/// arriving directly.
const MAX_TUNNELLED_BODY_BYTES: usize = 4 * 1024 * 1024;
use tower::ServiceExt;

use mcpg_tunnel_proto::{
    AgentSession, AttestedMeta, Frame, FrameStream, ProtoError, RequestHead, ResponseHead,
};

/// A hook the caller (the gateway) uses to add request extensions the engine
/// can't build generically — chiefly the gateway's own `TlsInfo` derived from
/// [`AttestedMeta::tls`], so its mTLS identity plugins see the client cert.
/// The engine has already inserted [`ConnectInfo`] before this runs.
pub type RequestDecorator = Arc<dyn Fn(&mut Request<Body>, &AttestedMeta) + Send + Sync>;

/// A no-op decorator, for callers with no extra extensions to add (and tests).
pub fn no_decorator() -> RequestDecorator {
    Arc::new(|_req, _attested| {})
}

/// Serve a tunnel: accept request streams until the session closes, handling
/// each concurrently against `router`. Returns when the relay hangs up.
pub async fn serve(
    mut session: AgentSession,
    router: Router,
    decorate: RequestDecorator,
) -> Result<(), ProtoError> {
    while let Some(stream) = session.accept().await {
        let router = router.clone();
        let decorate = decorate.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(stream, router, decorate).await {
                tracing::debug!(error = %e, "tunnel request failed");
            }
        });
    }
    Ok(())
}

/// Handle one request stream: read the request, run it through the router,
/// stream the response back.
async fn handle_request(
    mut stream: FrameStream,
    router: Router,
    decorate: RequestDecorator,
) -> Result<(), ProtoError> {
    let head = match stream.recv().await? {
        Some(Frame::RequestHead(h)) => h,
        // A stream that closes before its head is a benign abort, not an error.
        None => return Ok(()),
        Some(other) => {
            return Err(ProtoError::Protocol(format!(
                "expected RequestHead, got {other:?}"
            )));
        }
    };

    // Collect the request body. MCP request bodies are small JSON; buffering
    // is fine (only the *response* side needs to stream, for SSE).
    //
    // The cap is what makes that assumption safe. `MAX_FRAME_LEN` bounds one
    // frame, not the aggregate, so without this a peer streams unlimited
    // BodyChunk frames into a single allocation on the agent — which sits
    // inside the gateway process and never saw the transport's own body
    // limit, because the tunnel delivers a request that was already framed.
    let mut body = Vec::new();
    loop {
        match stream.recv().await? {
            Some(Frame::BodyChunk(chunk)) => {
                if body.len().saturating_add(chunk.len()) > MAX_TUNNELLED_BODY_BYTES {
                    tracing::warn!(
                        limit = MAX_TUNNELLED_BODY_BYTES,
                        "tunnelled request body exceeds the limit; dropping the request"
                    );
                    return Ok(());
                }
                body.extend_from_slice(&chunk);
            }
            Some(Frame::BodyEnd) => break,
            // The client aborted mid-body; drop the request.
            Some(Frame::Error(_)) | None => return Ok(()),
            Some(other) => {
                return Err(ProtoError::Protocol(format!(
                    "expected body frame, got {other:?}"
                )));
            }
        }
    }

    let mut request = build_request(&head, body)?;
    if let Some(ip) = head.attested.client_ip {
        // Port is unknown over the tunnel (the relay attests the address, not
        // the ephemeral source port); the rate limiter keys on the IP only.
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 0)));
    }
    decorate(&mut request, &head.attested);

    // axum's `Router` is an infallible `Service`, so the error is uninhabited.
    let response = tokio::select! {
        response = router.oneshot(request) => response.unwrap_or_else(|e: Infallible| match e {}),
        () = relay_let_go(&mut stream) => return Ok(()),
    };

    let (parts, mut resp_body) = response.into_parts();
    stream
        .send(Frame::ResponseHead(ResponseHead {
            status: parts.status.as_u16(),
            headers: header_pairs(&parts.headers),
        }))
        .await?;

    // Stream the response body frame-by-frame so SSE events flow as produced.
    loop {
        let frame = tokio::select! {
            frame = resp_body.frame() => frame,
            () = relay_let_go(&mut stream) => return Ok(()),
        };
        let Some(frame) = frame else { break };
        let frame = frame.map_err(|e| ProtoError::Io(std::io::Error::other(e.to_string())))?;
        if let Ok(data) = frame.into_data()
            && !data.is_empty()
        {
            stream.send(Frame::BodyChunk(data)).await?;
        }
    }
    stream.send(Frame::BodyEnd).await?;
    stream.close().await?;
    Ok(())
}

/// Resolves once the relay lets go of a request's stream: it sends nothing
/// after the request body, so whatever arrives (its reset when the client
/// went away or the response head came too late) means no one reads the
/// response. The request is then dropped, as a direct client's disconnect
/// drops it, and the stream stops counting against the session's limit.
async fn relay_let_go(stream: &mut FrameStream) {
    let _ = stream.recv().await;
}

fn build_request(head: &RequestHead, body: Vec<u8>) -> Result<Request<Body>, ProtoError> {
    let uri = match &head.query {
        Some(q) => format!("{}?{}", head.path, q),
        None => head.path.clone(),
    };
    let method = Method::from_bytes(head.method.as_bytes())
        .map_err(|_| ProtoError::Protocol(format!("invalid method: {}", head.method)))?;

    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in &head.headers {
        // Skip malformed header names/values rather than failing the request.
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(n, v);
        }
    }
    builder
        .body(Body::from(body))
        .map_err(|e| ProtoError::Protocol(e.to_string()))
}

fn header_pairs(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_owned(), s.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::sse::{Event, Sse};
    use axum::routing::{get, post};
    use futures::stream;
    use mcpg_tunnel_proto::{
        Exposure, HandshakeRequest, HandshakeResponse, RelaySession, TrustMode, TunnelSpec,
    };
    use std::convert::Infallible as StdInfallible;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_router() -> Router {
        Router::new()
            .route(
                "/mcp",
                post(|body: String| async move { format!("echo:{body}") }),
            )
            // An endpoint that reflects the rate-limit-critical client IP, to
            // prove ConnectInfo injection reaches handlers.
            .route(
                "/whoami",
                get(|ConnectInfo(addr): ConnectInfo<SocketAddr>| async move { addr.ip().to_string() }),
            )
            // A streaming SSE endpoint, to prove the response body streams
            // frame-by-frame through the tunnel.
            .route(
                "/events",
                get(|| async {
                    let events = stream::iter(
                        ["a", "b", "c"]
                            .into_iter()
                            .map(|d| Ok::<_, StdInfallible>(Event::default().data(d))),
                    );
                    Sse::new(events)
                }),
            )
    }

    fn private_spec() -> TunnelSpec {
        TunnelSpec {
            name: None,
            exposure: Exposure::Private,
            mode: TrustMode::RelayTerminated,
        }
    }

    async fn ok_handshake(req: &HandshakeRequest) -> Result<HandshakeResponse, ProtoError> {
        Ok(HandshakeResponse {
            accepted_proto_version: req.proto_version.clone(),
            tunnel_id: "t-1".to_owned(),
            public_url: None,
            heartbeat_secs: 30,
        })
    }

    /// Boot an agent serving `test_router()` over one end of an in-memory
    /// duplex; return the relay session on the other end. Both handshake
    /// halves must run concurrently — awaiting the agent's connect before the
    /// relay's accept would deadlock, since the agent blocks on a handshake
    /// response the relay hasn't started producing.
    async fn boot() -> RelaySession {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (agent_res, relay_res) = tokio::join!(
            AgentSession::connect(client_io, HandshakeRequest::new("inst-1", private_spec())),
            RelaySession::accept(server_io, ok_handshake),
        );
        let (agent, _resp) = agent_res.unwrap();
        let (relay, _req) = relay_res.unwrap();
        tokio::spawn(serve(agent, test_router(), no_decorator()));
        relay
    }

    /// Drive one request over a relay-opened stream and collect (status, body).
    async fn call(relay: &RelaySession, head: RequestHead, body: &[u8]) -> (u16, Vec<u8>) {
        let mut s = relay.open_request().await.unwrap();
        s.send(Frame::RequestHead(head)).await.unwrap();
        if !body.is_empty() {
            s.send(Frame::BodyChunk(bytes::Bytes::copy_from_slice(body)))
                .await
                .unwrap();
        }
        s.send(Frame::BodyEnd).await.unwrap();

        let status = match s.recv().await.unwrap().unwrap() {
            Frame::ResponseHead(h) => h.status,
            other => panic!("expected ResponseHead, got {other:?}"),
        };
        let mut out = Vec::new();
        loop {
            match s.recv().await.unwrap() {
                Some(Frame::BodyChunk(b)) => out.extend_from_slice(&b),
                Some(Frame::BodyEnd) | None => break,
                other => panic!("unexpected response frame: {other:?}"),
            }
        }
        (status, out)
    }

    fn head(method: &str, path: &str, attested: AttestedMeta) -> RequestHead {
        RequestHead {
            method: method.to_owned(),
            path: path.to_owned(),
            query: None,
            headers: vec![],
            attested,
        }
    }

    #[tokio::test]
    async fn post_body_is_echoed_through_the_router() {
        let relay = boot().await;
        let (status, body) = call(
            &relay,
            head("POST", "/mcp", AttestedMeta::default()),
            b"hello",
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(&body, b"echo:hello");
    }

    #[tokio::test]
    async fn attested_client_ip_reaches_the_handler_via_connectinfo() {
        let relay = boot().await;
        let attested = AttestedMeta {
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            tls: None,
        };
        let (status, body) = call(&relay, head("GET", "/whoami", attested), b"").await;
        assert_eq!(status, 200);
        assert_eq!(&body, b"203.0.113.7");
    }

    #[tokio::test]
    async fn sse_response_streams_through_the_tunnel() {
        let relay = boot().await;
        let (status, body) =
            call(&relay, head("GET", "/events", AttestedMeta::default()), b"").await;
        assert_eq!(status, 200);
        let text = String::from_utf8(body).unwrap();
        // Each SSE event arrived as its own data line.
        assert!(text.contains("data: a"), "missing event a in {text:?}");
        assert!(text.contains("data: b"), "missing event b in {text:?}");
        assert!(text.contains("data: c"), "missing event c in {text:?}");
    }

    /// Counts its own drops, so a test can tell when a handler or a response
    /// body was abandoned.
    struct DropCount(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    async fn until_counted(count: &std::sync::atomic::AtomicUsize, n: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while count.load(std::sync::atomic::Ordering::SeqCst) < n {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("count reaches {n}"));
    }

    /// A request the relay lets go of (its client went away, or its response
    /// head came too late) is abandoned on the agent too, as a direct
    /// client's disconnect abandons it: a handler still running and a
    /// response still streaming are both dropped.
    #[tokio::test]
    async fn a_request_the_relay_lets_go_of_is_abandoned() {
        use futures::StreamExt as _;
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/slow",
                post({
                    let (started, dropped) = (started.clone(), dropped.clone());
                    move || async move {
                        started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let _guard = DropCount(dropped);
                        std::future::pending::<()>().await;
                        "late"
                    }
                }),
            )
            .route(
                "/stream",
                get({
                    let dropped = dropped.clone();
                    move || async move {
                        let guard = DropCount(dropped);
                        let first = stream::once(async {
                            Ok::<_, StdInfallible>(Event::default().data("a"))
                        });
                        Sse::new(first.chain(stream::pending()).map(move |event| {
                            let _ = &guard;
                            event
                        }))
                    }
                }),
            );
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (agent_res, relay_res) = tokio::join!(
            AgentSession::connect(client_io, HandshakeRequest::new("inst-1", private_spec())),
            RelaySession::accept(server_io, ok_handshake),
        );
        let (agent, _resp) = agent_res.unwrap();
        let (relay, _req) = relay_res.unwrap();
        tokio::spawn(serve(agent, router, no_decorator()));

        let mut s = relay.open_request().await.unwrap();
        let slow = head("POST", "/slow", AttestedMeta::default());
        s.send(Frame::RequestHead(slow)).await.unwrap();
        s.send(Frame::BodyEnd).await.unwrap();
        until_counted(&started, 1).await;
        drop(s);
        until_counted(&dropped, 1).await;

        let mut s = relay.open_request().await.unwrap();
        let streaming = head("GET", "/stream", AttestedMeta::default());
        s.send(Frame::RequestHead(streaming)).await.unwrap();
        s.send(Frame::BodyEnd).await.unwrap();
        assert!(matches!(s.recv().await, Ok(Some(Frame::ResponseHead(_)))));
        assert!(matches!(s.recv().await, Ok(Some(Frame::BodyChunk(_)))));
        drop(s);
        until_counted(&dropped, 2).await;
    }

    #[tokio::test]
    async fn unknown_route_returns_404_not_a_tunnel_error() {
        let relay = boot().await;
        let (status, _body) =
            call(&relay, head("GET", "/nope", AttestedMeta::default()), b"").await;
        assert_eq!(status, 404);
    }
}
