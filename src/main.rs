use microscope::{db, web::AppState, web::router};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    let mut addr = String::from("127.0.0.1:5248");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--addr" {
            if let Some(v) = args.next() {
                addr = v;
            }
        }
    }
    let data_dir = PathBuf::from("data");
    std::fs::create_dir_all(data_dir.join("incoming")).ok();
    let conn = db::open(&data_dir.join("microscope.db")).expect("打开数据库失败");
    let state = AppState {
        conn: Arc::new(Mutex::new(conn)),
        data_dir: Arc::new(data_dir),
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("绑定地址失败");
    println!("包链显微镜: http://{addr}");
    axum::serve(listener, app).await.expect("server error");
}
