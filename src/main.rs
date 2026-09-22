use std::net::SocketAddr;
use std::path::PathBuf;
use pack_microscope::engine::Engine;
use pack_microscope::web::build_router;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut addr: SocketAddr = "127.0.0.1:5248".parse().unwrap();
    let mut data_dir = PathBuf::from("data");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                addr = args
                    .get(i)
                    .expect("--addr needs a value")
                    .parse()
                    .expect("invalid socket address");
            }
            "--data-dir" => {
                i += 1;
                data_dir = PathBuf::from(args.get(i).expect("--data-dir needs a value"));
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let engine = std::sync::Arc::new(Engine::new(data_dir).expect("engine init failed"));
    // Re-run analysis on startup so a freshly populated data dir is current.
    let _ = engine.analyze();
    let app = build_router(engine);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind failed");
    println!("包链显微镜 listening on http://{addr}");
    axum::serve(listener, app).await.expect("server failed");
}
