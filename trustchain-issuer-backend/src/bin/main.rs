use actix_web::{web, App, HttpServer};
use trustchain_issuer_backend::handlers;

// Process sketch:
// 0. Issuer visits "/issuer/" page and completes POST request with (e.g. a name) routing to "/issuer/post1"
//    This step does not currently further incorporate data from the POST and is illustrative.
// 1. User visits "/issuer/post1" page, and is displayed a QR code of a URL (with UUID) to send GET
//    request to receive a credential offer.
// 2. Within credible app, scan QR code of address which performs GET
// 3. Server receives get request and returns a credential offer with UUID from URI
// 4. Credible receives offer and returns POST with any user info (i.e. the DID)
// 5. Server receives POST data, checks it is valid for UUID and returns a signed credential with offer
// 6. Credible receives response and verifies credential received using the Trustchain server

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    HttpServer::new(|| {
        App::new()
            .service(web::resource("/").route(web::get().to(handlers::index)))
            .service(web::resource("/issuer").route(web::get().to(handlers::issuer)))
            .service(
                web::resource("/issuer/post1").route(web::post().to(handlers::get_issuer_qrcode)),
            )
            .service(web::resource("/verifier").route(web::get().to(handlers::get_verifier_qrcode)))
            .service(handlers::get_issuer)
            .service(handlers::post_issuer)
            .service(handlers::get_verifier)
            .service(handlers::post_verifier)
            .service(handlers::get_did)
            .service(handlers::get_chain)
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
