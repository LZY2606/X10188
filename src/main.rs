use std::net::SocketAddr;

use pack_chain_microscope::{database::Database, server::build_router, AnalysisSystem};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_addr(std::env::args().skip(1).collect())?;
    let data_dir = std::env::current_dir()?.join("data");
    std::fs::create_dir_all(&data_dir)?;
    let db = Database::open(data_dir.join("microscope.sqlite"))?;
    let system = AnalysisSystem::new(data_dir.clone(), db);
    system.bootstrap()?;

    let app = build_router(std::sync::Arc::new(system));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("包链显微镜 listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn parse_addr(args: Vec<String>) -> Result<SocketAddr, String> {
    let mut addr: SocketAddr = "127.0.0.1:5248".parse().unwrap();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--addr" {
            let value = iter.next().ok_or_else(|| "--addr requires a value")?;
            addr = value.parse().map_err(|err| format!("invalid address: {err}"))?;
        } else if let Some(value) = arg.strip_prefix("--addr=") {
            addr = value.parse().map_err(|err| format!("invalid address: {err}"))?;
        }
    }
    Ok(addr)
}
