use pack_microscope::{api, importer, store::Store};
use std::net::SocketAddr;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let mut addr: SocketAddr = "127.0.0.1:5248".parse().unwrap();
    let mut data_dir = PathBuf::from("data");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--addr" => {
                if let Some(v) = args.next() {
                    addr = v.parse().expect("valid socket address");
                }
            }
            "--data-dir" => {
                if let Some(v) = args.next() {
                    data_dir = PathBuf::from(v);
                }
            }
            other => eprintln!("ignoring unknown argument: {}", other),
        }
    }

    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let store = Store::open(&data_dir).expect("open store");
    let state = api::AppState::new(store, data_dir.clone());
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("包链显微镜 listening on http://{} (data: {:?})", addr, data_dir);
    axum::serve(listener, app).await.expect("server");
}

// Keep import referenced for binary-only usage helpers.
#[allow(dead_code)]
fn _touch() {
    let _ = importer::MAX_OBJECT_BYTES;
}
