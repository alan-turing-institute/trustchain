use actix_web::{web, App, HttpServer};
use trustchain_issuer_backend::handlers;

// Process sketch:
// 1. User visits "credentials/" page and is displayed a QR code of a URI (with UUID) to send GET request to
//    - Post request could contain: Name, DID (optionally), other stuff?
// 2. Within credible app, scan QR code of address which performs GET
// 3. Server receives get request and returns a credential offer with UUID from URI
// 4. Credible receives offer and returns POST with any user info (i.e. the DID)
// 5. Server receives POST data, checks it is valid for UUID and returns a signed credential with offer
// 6. Credible receives response and verifies credential received using the Trustchain server

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(handlers::greet)
            .service(handlers::get_vc_offer)
            .service(handlers::post_request)
            .service(web::resource("/").route(web::get().to(handlers::index)))
            .service(web::resource("/issuer").route(web::get().to(handlers::issuer)))
            .service(
                web::resource("/issuer/post1")
                    .route(web::post().to(handlers::handle_issuer_post_start)),
            )
            .service(web::resource("/verifier").route(web::get().to(handlers::vp_offer_address)))
            .service(handlers::get_vp_offer)
            .service(handlers::post_request_verifier)
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
