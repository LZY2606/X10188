use std::net::SocketAddr;
use std::path::PathBuf;

fn parse_args() -> (SocketAddr, PathBuf) {
    let mut args = std::env::args().skip(1);
    let mut addr: SocketAddr = "127.0.0.1:5248".parse().unwrap();
    let mut data_dir = PathBuf::from("data");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--addr" => {
                let v = args.next().expect("--addr requires value");
                addr = v.parse().expect("invalid socket address");
            }
            "--data-dir" => {
                data_dir = PathBuf::from(args.next().expect("--data-dir requires value"));
            }
            other => panic!("unknown argument {other}"),
        }
    }
    (addr, data_dir)
}

#[tokio::main]
async fn main() {
    let (addr, data_dir) = parse_args();
    let engine = pack_microscope::engine::Engine::new(&data_dir).expect("open engine");
    let app = pack_microscope::web::app(engine);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    eprintln!(
        "包链显微镜 listening on http://{addr} (data dir: {})",
        data_dir.display()
    );
    axum::serve(listener, app).await.expect("serve");
}
