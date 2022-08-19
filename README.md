# trustchain
Decentralised public key infrastructure

## Backend
Rust backend library can be written inside `src/`. See
e.g. [`src/lib.rs`](src/lib.rs) and [`src/lib.rs`](src/utils.rs).

You can basically write code as if Rust only and then expose Rust functions to
the `wasm-pack` build with:
```rust
#[wasm_bindgen]
pub fn my_fn_to_call_from_js_frontend() {
}
```

To build so that it is packaged for the javascript, just call:
```rust
wasm-pack build
```


## Frontend
We can write this inside the path [`www/`](www/). Inside this path call:
```bash
npm install
npm run start
```
and a local server is run displaying [`www/index.html`](www/index.html),
which runs the javascript in [`www/index.js`](www/index.js).

For the frontend, we can write some basic code in `www/index.js` and test out
some mock Rust functions to experiment with how we would like it to look and
work as an API.
