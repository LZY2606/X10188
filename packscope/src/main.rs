//! 包链显微镜 (Pack Chain Microscope) — zero-dependency Git pack/delta forensics.

mod api_data;
mod db;
mod delta;
mod engine;
mod gitfmt;
mod ingest;
mod pack;
mod ui;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
struct Args {
    addr: SocketAddr,
    data_dir: PathBuf,
}

fn parse_args() -> Args {
    let mut addr: SocketAddr = "127.0.0.1:5248".parse().unwrap();
    let mut data_dir = PathBuf::from("packscope_data");
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().expect("--addr 需要值").parse().expect("无效地址"),
            "--data-dir" => data_dir = PathBuf::from(it.next().expect("--data-dir 需要值")),
            other => panic!("未知参数 {other}（支持 --addr 与 --data-dir）"),
        }
    }
    Args { addr, data_dir }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args();
    let db = db::Db::open(&args.data_dir)?;
    // Build an initial analysis view on startup.
    let _ = db.analyze_branch(1);
    let app = web::router(db);
    let listener = tokio::net::TcpListener::bind(args.addr).await?;
    eprintln!("包链显微镜 已启动: http://{}", args.addr);
    axum::serve(listener, app).await?;
    Ok(())
}
