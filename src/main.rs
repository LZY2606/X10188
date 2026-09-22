use std::net::SocketAddr;
use std::path::PathBuf;

use microscope::{web::router, AppState};

#[derive(Debug)]
struct Args {
    addr: String,
    data_dir: PathBuf,
}

fn parse_args() -> Args {
    let mut args = pico_args();
    let mut a = Args {
        addr: "127.0.0.1:5248".to_string(),
        data_dir: PathBuf::from("data"),
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--addr" | "-a" => {
                if let Some(v) = iter.next() {
                    a.addr = v;
                }
            }
            "--data-dir" | "-d" => {
                if let Some(v) = iter.next() {
                    a.data_dir = PathBuf::from(v);
                }
            }
            "--help" | "-h" => {
                println!("包链显微镜\n  --addr <IP:PORT>   listen address (default 127.0.0.1:5248)\n  --data-dir <DIR>   project data directory (default ./data)");
                std::process::exit(0);
            }
            other => eprintln!("ignoring unknown argument: {other}"),
        }
    }
    a
}

fn pico_args() {}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let addr: SocketAddr = args
        .addr
        .parse()
        .unwrap_or_else(|e| panic!("bad --addr {}: {e}", args.addr));
    let state = AppState::open(&args.data_dir).expect("open data dir");
    let app = router(std::sync::Arc::new(state));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("包链显微镜 listening on http://{addr}  (data: {})", args.data_dir.display());
    axum::serve(listener, app).await.expect("server");
}
