use std::net::SocketAddr;
use std::path::PathBuf;

use packchain_microscope::Engine;

mod web;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut addr: SocketAddr = "127.0.0.1:5248".parse().unwrap();
    let mut data_dir = PathBuf::from("data");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--addr" => {
                if let Some(v) = args.next() {
                    addr = v.parse().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
                    })?;
                }
            }
            "--data-dir" => {
                if let Some(v) = args.next() {
                    data_dir = PathBuf::from(v);
                }
            }
            other => {
                eprintln!("未知参数 {other}（支持 --addr <addr> 与 --data-dir <dir>）");
            }
        }
    }

    let engine = std::sync::Arc::new(Engine::open(&data_dir)?);
    let app = web::app(engine);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("包链显微镜 正在监听 http://{addr}（数据目录 {}）", data_dir.display());
    axum::serve(listener, app).await
}
