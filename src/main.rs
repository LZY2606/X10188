use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use packscope::store::Store;
use packscope::web::router;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    let addr = parse_addr(std::env::args().skip(1).collect());
    let data_dir = PathBuf::from("data");
    std::fs::create_dir_all(data_dir.join("sources")).expect("create data directory");
    let store = Store::open(&data_dir).expect("open sqlite store");
    let app = router(Arc::new(Mutex::new(store)), data_dir);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind address");
    axum::serve(listener, app).await.expect("run server");
}

fn parse_addr(args: Vec<String>) -> SocketAddr {
    let mut addr: SocketAddr = "127.0.0.1:5248".parse().unwrap();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--addr" {
            if let Some(value) = iter.next() {
                addr = value.parse().expect("valid socket address");
            }
        } else if let Some(value) = arg.strip_prefix("--addr=") {
            addr = value.parse().expect("valid socket address");
        }
    }
    addr
}
