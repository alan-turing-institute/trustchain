use base64::engine::general_purpose;
use base64::write::EncoderWriter;
use gloo_console::log;
use image::Luma;
use image::{DynamicImage, ImageOutputFormat};
use qrcode::QrCode;
use yew::prelude::*;

pub fn image_to_base64_string(image: &DynamicImage) -> String {
    let mut buf = Vec::new();
    {
        let mut writer = EncoderWriter::new(&mut buf, &general_purpose::STANDARD);
        image.write_to(&mut writer, ImageOutputFormat::Png).unwrap();
    }
    std::str::from_utf8(&buf).unwrap().to_string()
}

#[function_component(App)]
pub fn app() -> Html {
    // Encode some data into bits.
    let code = QrCode::new(b"http://10.0.2.2:8081/vc/abc").unwrap();

    // Render the bits into an image.
    let image = DynamicImage::ImageLuma8(code.render::<Luma<u8>>().build());
    let image_str = image_to_base64_string(&image);
    let image_str = format!("data:image/png;base64,{}", image_str);

    // Log string for debug
    log!(image_str.clone());

    // Place image in html
    html! {
        <div>
            <img src={image_str} />
        </div>
    }
}
