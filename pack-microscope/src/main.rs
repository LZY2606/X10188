use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let mut addr: SocketAddr = "127.0.0.1:5248".parse().unwrap();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--addr" => {
                if let Some(v) = iter.next() {
                    addr = v.parse().expect("invalid socket address");
                }
            }
            "--data-dir" => {
                if let Some(v) = iter.next() {
                    std::env::set_var("PAIM_DATA_DIR", v);
                }
            }
            other => {
                eprintln!("未知参数: {}", other);
                std::process::exit(2);
            }
        }
    }
    let app = pack_microscope::web::app();
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind failed");
    println!("包链显微镜监听 http://{}", addr);
    axum::serve(listener, app).await.expect("server error");
}
