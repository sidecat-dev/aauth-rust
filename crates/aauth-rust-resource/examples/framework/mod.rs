//! Example-specific axum adapter for a trusted private proxy hop.
use aauth_rust_core::AgentProviderKeys;
use aauth_rust_resource::{AgentIdentityResource, BoxedAdmissionPolicy};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    routing::{any, get},
};
use http::{Request, Response, StatusCode, Uri};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// Shared issuer keys and a policy carrying an application account into handlers.
pub type Resource = AgentIdentityResource<Arc<AgentProviderKeys>, BoxedAdmissionPolicy<String>>;

struct Gate {
    origin: Uri,
    resource: Arc<Resource>,
}

/// Wall clock in Unix seconds, used only by this example.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

/// One route bound to its configured external HTTPS origin, behind a trusted proxy.
pub fn router(origin: Uri, resource: Arc<Resource>) -> Router {
    Router::new()
        .route("/whoami", any(gate))
        .route("/.well-known/aauth-resource.json", get(metadata))
        .with_state(Arc::new(Gate { origin, resource }))
}

async fn gate(State(state): State<Arc<Gate>>, request: Request<Body>) -> Response<Body> {
    let (mut parts, body) = request.into_parts();
    let body = match to_bytes(body, 1024).await {
        Ok(body) => body.to_vec(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from("body exceeds the 1 KiB adapter limit"))
                .unwrap();
        }
    };
    // Keep actual method, path/query and headers. Host/Forwarded do not set origin.
    let mut target = parts.uri.into_parts();
    target.scheme = state.origin.scheme().cloned();
    target.authority = state.origin.authority().cloned();
    parts.uri = match Uri::from_parts(target) {
        Ok(uri) => uri,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())
                .unwrap();
        }
    };
    let request = Request::from_parts(parts, body);
    match state.resource.authorize(&request, now()).into_result() {
        Ok((token, account)) => Response::new(Body::from(format!(
            "verified {} account={account}\n",
            token.claims().sub
        ))),
        Err(response) => (*response).map(Body::from),
    }
}

async fn metadata(State(state): State<Arc<Gate>>) -> Response<Body> {
    match state.resource.metadata() {
        Ok(bytes) => Response::builder()
            .header("content-type", "application/json")
            .body(Body::from(bytes))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(
                "configure a canonical external Resource identity",
            ))
            .unwrap(),
    }
}
