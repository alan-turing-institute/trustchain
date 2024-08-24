//! Static handlers for front-end.
use axum::response::Html;

pub async fn index() -> Html<String> {
    Html(
        std::fs::read_to_string(format!("{}/static/index.html", env!("CARGO_MANIFEST_DIR")))
            .unwrap(),
    )
}
pub async fn issuer() -> Html<String> {
    Html(
        std::fs::read_to_string(format!("{}/static/issuer.html", env!("CARGO_MANIFEST_DIR")))
            .unwrap(),
    )
}
