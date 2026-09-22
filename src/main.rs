use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use pack_microscope::{web, Engine};

/// 包链显微镜：Git pack / index / loose object 取证分析服务。
#[derive(Parser, Debug)]
#[command(name = "pack-microscope", version)]
struct Args {
    /// 监听地址。
    #[arg(long, default_value = "127.0.0.1:5248")]
    addr: String,
    /// 项目数据目录（所有导入文件与 SQLite 都留在这里）。
    #[arg(long, default_value = "./data")]
    data_dir: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let engine = Arc::new(
        Engine::open(std::path::Path::new(&args.data_dir)).expect("打开数据目录失败"),
    );
    let app = web::router(engine);
    let addr: SocketAddr = args.addr.parse().expect("无效的监听地址");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("绑定监听地址失败");
    println!("包链显微镜 已启动：http://{}", addr);
    axum::serve(listener, app).await.expect("服务异常退出");
}
