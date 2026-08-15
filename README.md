# mcpg-tunnel-agent

> The tunnel agent's request engine: replays tunnel-borne requests through an axum `Router` with no local TCP bind.

The agent end of an MCPG reverse tunnel. `serve` accepts the request streams a
relay opens and, for each, reconstructs the original `http::Request`, stamps the
relay-attested origin onto it, and drives it through the caller's own
`axum::Router` with `oneshot` — so the request traverses the exact same
middleware, identity, policy, and streaming path it would over a real listener,
while the process binds no port at all. Response bodies, including Server-Sent
Events, stream back frame by frame as they are produced. Reach for it when a
service behind NAT or a corporate firewall has to answer requests that arrive
from a public relay. The crate carries no dialing, TLS, authentication, or
reconnection logic; a caller supplies the already-connected session.

## What's here

- `serve(session, router, decorate)` — the accept loop. Takes an
  `AgentSession` from `mcpg-tunnel-proto`, handles each inbound stream on its
  own task, and returns when the relay hangs up.
- `RequestDecorator` — `Arc<dyn Fn(&mut Request<Body>, &AttestedMeta) + Send + Sync>`,
  the hook a caller uses to add request extensions the engine cannot build
  generically. The gateway uses it to map `AttestedMeta::tls` onto its own TLS
  info type so mTLS identity plugins see the client certificate.
- `no_decorator()` — a no-op decorator, for callers with nothing extra to add.

## Request handling

One mux stream carries one exchange. The engine reads a `RequestHead`, buffers
the body, rebuilds method, path, query, and headers, runs the router, sends a
`ResponseHead`, then streams body frames until the response body ends and closes
the stream.

Request bodies are buffered rather than streamed — MCP request bodies are small
JSON, and only the response side needs to stream. That assumption is made safe
by a 4 MiB ceiling on the aggregate buffered body, matching the gateway
transport's own default request-body limit so a tunnelled request is held to the
same bound as a direct one. The frame codec's per-frame cap bounds a single
frame, not the total, so without this ceiling a peer could stream unlimited body
chunks into one allocation inside the process. A request that exceeds it is
dropped with a warning.

Malformed input degrades rather than escalating: a header whose name or value
will not parse is skipped instead of failing the request, a stream that closes
before its head is treated as a benign abort, and a client abort mid-body drops
the request. An out-of-order frame — a body chunk before a head, say — is a
protocol violation and is reported as one.

## Security

Injecting the attested `ConnectInfo` is security-critical rather than cosmetic.
A gateway's per-IP anonymous rate limiter reads the peer address from that
extension and treats a request without one as unattributable — it skips limiting
rather than lumping every such caller into a shared bucket — so a tunnelled
request arriving without a peer address would bypass anonymous rate limiting
entirely. The engine inserts `ConnectInfo(SocketAddr)` built from
`AttestedMeta::client_ip`, which is the address the relay observed on the public
connection and never a client-supplied header. The source port is not carried
over the tunnel and is stamped as zero; the limiter keys on the IP alone.

The decorator runs *after* that insertion, so a caller can add its own
extensions but is not responsible for origin attribution.

## Used by

- `apps/gateway` — the `mcpg --tunnel` transport, which supplies the dialled
  session, the gateway router, and a decorator that reconstructs TLS metadata.
- The managed relay broker — as a dev/test counterpart to its forwarding
  core. That service is hosted and not part of this repository.

## Usage

The crate is not published to crates.io; depend on it by path from within this
workspace.

```toml
[dependencies]
mcpg-tunnel-agent = { path = "../tunnel-agent" }
mcpg-tunnel-proto = { path = "../tunnel-proto" }
```

```rust
use mcpg_tunnel_agent::{no_decorator, serve};
use mcpg_tunnel_proto::{AgentSession, HandshakeRequest};

// `transport` is any AsyncRead + AsyncWrite the caller has already
// connected and authenticated.
let (session, _resp) =
    AgentSession::connect(transport, HandshakeRequest::new("inst-1", spec)).await?;

serve(session, router, no_decorator()).await?;
```

A decorator receives the attested metadata alongside the rebuilt request, after
`ConnectInfo` has been inserted:

```rust
use std::sync::Arc;
use mcpg_tunnel_agent::RequestDecorator;

let decorate: RequestDecorator = Arc::new(|req, attested| {
    if let Some(tls) = &attested.tls {
        req.extensions_mut().insert(my_tls_info(tls));
    }
});
```

The crate targets Rust edition 2024.

## Build / test

```bash
cargo build -p mcpg-tunnel-agent
cargo test  -p mcpg-tunnel-agent
```

The tests run a real agent and relay over an in-memory duplex and assert the
properties that matter: a POST body round-trips through the router, the attested
client IP reaches a handler via `ConnectInfo`, an SSE response arrives as
separate events, and an unknown route returns a 404 from the router rather than
a tunnel error.

## Licence

Apache-2.0.

## See also

- [Tunneling](https://mcpg.dev/docs/gateway/tunneling)
- [Reverse federation](https://mcpg.dev/articles/reverse-federation)
- `libs/tunnel-proto` — the frames, handshake, and session layer this engine
  runs on.
