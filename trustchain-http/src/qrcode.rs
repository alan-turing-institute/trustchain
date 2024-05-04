//! QR code functionality for encoding credential offers and presentation requests.
use base64::engine::general_purpose;
use base64::write::EncoderWriter;
use image::Luma;
use image::{DynamicImage, ImageOutputFormat};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// QR code JSON type of verifiable content.
pub(crate) struct DIDQRCode {
    /// DID for issuance and/or verifier endpoint resolution.
    pub did: String,
    /// HTTP route for making issuer or verifer requests.
    pub route: String,
    /// ID for identifying credential offer or presentation request.
    pub id: String,
}

pub fn image_to_base64_string(image: &DynamicImage) -> String {
    let mut buf = Vec::new();
    {
        let mut writer = EncoderWriter::new(&mut buf, &general_purpose::STANDARD);
        image.write_to(&mut writer, ImageOutputFormat::Png).unwrap();
    }
    std::str::from_utf8(&buf).unwrap().to_string()
}

pub fn str_to_qr_code_html(url: &str, title: &str) -> String {
    // Make QR code
    let code = QrCode::new(url.as_bytes()).unwrap();

    // Render the bits into an image.
    let image = DynamicImage::ImageLuma8(code.render::<Luma<u8>>().build());
    let image_str = image_to_base64_string(&image);
    let image_str = format!("data:image/png;base64,{}", image_str);
    let html = format!(
        "<!doctype html>
        <html>
            <head>
            <meta charset=utf-8>
            <title>{title}</title>
        </head>
        <body>
            <div>
            <a href={url}>
                <img src={image_str} />
            </div>
        </body>
        </html>"
    );
    html
}
