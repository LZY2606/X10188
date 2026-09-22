use clap::Parser;
use packchain_microscope::{db, web};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

#[derive(Parser)]
#[command(name = "packchain-microscope", about = "Git pack chain microscope")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:5248")]
    addr: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let base_dir = std::env::current_dir().unwrap().join("data");
    std::fs::create_dir_all(&base_dir).unwrap();
    let data_dir = base_dir.to_string_lossy().to_string();

    let db_path = base_dir.join("microscope.sqlite");
    let conn = db::open(&db_path.to_string_lossy()).expect("open sqlite");
    let db = Arc::new(db::Db(std::sync::Mutex::new(conn)));

    let state = web::AppState {
        db,
        data_dir,
        lock: Arc::new(AsyncMutex::new(())),
    };

    let listener = tokio::net::TcpListener::bind(&args.addr).await.unwrap();
    println!("包链显微镜 listening on http://{}", args.addr);
    axum::serve(listener, web::router(state)).await.unwrap();
}
