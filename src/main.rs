//! 包链显微镜 — 启动入口。
//!
//! 用法：`cargo run -- --addr 127.0.0.1:5248 [--data ./data]`

use std::sync::Arc;

use pack_microscope::store::Store;
use pack_microscope::web::router;

#[derive(Default)]
struct Args {
    addr: String,
    data: String,
}

fn parse_args() -> Args {
    let mut args = Args { addr: "127.0.0.1:5248".into(), data: "data".into() };
    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--addr" => args.addr = iter.next().expect("--addr 需要值"),
            "--data" => args.data = iter.next().expect("--data 需要值"),
            "-h" | "--help" => {
                println!("用法: pack_microscope --addr 127.0.0.1:5248 [--data ./data]");
                std::process::exit(0);
            }
            other if other.starts_with("--addr=") => args.addr = other["--addr=".len()..].into(),
            other if other.starts_with("--data=") => args.data = other["--data=".len()..].into(),
            other => {
                eprintln!("忽略未知参数：{other}");
            }
        }
    }
    args
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let store = Arc::new(Store::open(&args.data).expect("打开数据目录/数据库失败"));
    let app = router(store);

    let listener = tokio::net::TcpListener::bind(&args.addr).await.expect("绑定地址失败");
    println!("包链显微镜已启动：http://{}/ （数据目录 {}）", args.addr, args.data);
    axum::serve(listener, app).await.expect("server error");
}
