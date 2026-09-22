mod git;
mod schema;
mod service;
mod web;

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow_lite::Result<()> {
    tracing_subscriber::fmt::init();
    let addr_arg = std::env::args().nth(1);
    let addr: SocketAddr = match addr_arg.as_deref() {
        Some("--addr") => std::env::args().nth(2).expect("missing addr").parse()?,
        Some(value) => value.trim_start_matches("--addr=").parse()?,
        None => "127.0.0.1:5248".parse()?,
    };

    let service = service::Service::open("data")?;
    let app = web::app(service);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("包链显微镜 listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

mod anyhow_lite {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}
