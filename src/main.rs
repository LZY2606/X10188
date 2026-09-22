use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "pack-chain-microscope")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:5248")]
    addr: String,
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let data_dir = args.data_dir.unwrap_or_else(|| PathBuf::from("data"));
    std::fs::create_dir_all(&data_dir).unwrap();
    let db_path = data_dir.join("microscope.sqlite");
    let db = pack_chain_microscope::db::Db::open(db_path.to_str().unwrap()).unwrap();
    let state = Arc::new(pack_chain_microscope::api::AppState { db, data_dir });

    let app = pack_chain_microscope::api::router(state);
    let addr: SocketAddr = args.addr.parse().expect("valid --addr");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("包链显微镜 listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
