mod db;
mod git;
mod service;
mod web;

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut addr: SocketAddr = "127.0.0.1:5248".parse().unwrap();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--addr" {
            addr = args.next().expect("missing --addr value").parse().expect("invalid address");
        }
    }
    let data_dir = std::env::current_dir()?.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let app = web::app(service::Analyzer::open(data_dir)?);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
