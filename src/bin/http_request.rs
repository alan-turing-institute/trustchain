use trustchain::publisher::Publisher;

// Binary to resolve a passed DID from the command line.
fn main() {
    // 0. Make publisher
    let publisher = Publisher::new();

    // 1. Try to perform a get request
    let response = publisher
        .runtime
        .block_on(publisher.get("key", "application/json"));
    println!("body = \n{}", response.unwrap());

    // 2. Try a POST request
    let example_body = r##"{
        "type": "update",
        "didSuffix": "EiCWPckEQHqdvdMtVCBLgmsHnEWhPnhmvNDB9PLqjj165A",
        "revealValue": "EiDsNzgHxKBxRg_xnhYBLUavgNu-ZzZcww0mnFZ0d3Hsuw"
    }"##;
    let body = example_body;
    let response = publisher.runtime.block_on(publisher.post(body));
    println!("res = \n{}", response.unwrap());
}
