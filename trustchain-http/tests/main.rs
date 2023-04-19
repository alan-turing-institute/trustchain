use axum::{routing::get, Router};
use clap::Parser;
use trustchain_http::{config::ServerConfig, handlers, issuer, resolver, verifier};

// Setup based on https://github.com/spruceid/didkit/blob/main/http/tests/main.rs

fn serve() -> (String, impl FnOnce() -> ()) {
    // TODO: Wrap and import this for reuse here and in main - add get_app to lib.rs
    let config: ServerConfig = Parser::parse();

    let app = Router::new()
        .route("/", get(handlers::index))
        .route("/issuer", get(issuer::get_issuer_qrcode))
        .route("/verifier", get(verifier::get_verifier_qrcode))
        .route(
            "/vc/issuer/:id",
            get(issuer::get_issuer).post(issuer::post_issuer),
        )
        .route(
            "/vc/verifier",
            get(verifier::get_verifier).post(verifier::post_verifier),
        )
        .route("/did/:id", get(resolver::get_did_resolver))
        .route(
            "/did/chain/:id",
            get(resolver::TrustchainHTTPHandler::get_did_chain),
        )
        .with_state(config.clone());

    let addr = ([127, 0, 0, 1], 0).into();
    let server = axum::Server::bind(&addr).serve(app.into_make_service());
    let url = "http://".to_string() + &server.local_addr().to_string();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let shutdown = || shutdown_tx.send(()).unwrap();
    let graceful = server.with_graceful_shutdown(async {
        shutdown_rx.await.unwrap();
    });
    tokio::task::spawn(async move {
        graceful.await.unwrap();
    });
    (url, shutdown)
}

#[tokio::test]
async fn not_found() {
    let (base, shutdown) = serve();
    let client = hyper::Client::builder().build_http::<hyper::Body>();
    let uri = (&(base + "/nonexistent-path"))
        .parse::<hyper::Uri>()
        .unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status(), 404);

    shutdown();
}

#[tokio::test]
async fn resolve_did() {
    let (base, shutdown) = serve();
    let client = hyper::Client::builder().build_http::<hyper::Body>();
    let uri = (&(base + "/did/abc")).parse::<hyper::Uri>().unwrap();
    let resp = client.get(uri).await.unwrap();
    let b = hyper::body::to_bytes(resp.into_body()).await;
    let bytes = match b {
        Ok(bs) => bs,
        _ => panic!(),
    };
    assert_eq!(bytes, "error");
    shutdown();
}
