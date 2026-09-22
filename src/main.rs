use packchain_microscope::{engine::{Analyzer, Budget}, web::serve};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut addr: SocketAddr = "127.0.0.1:5248".parse()?;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--addr" {
            addr = args.next().ok_or("missing --addr value")?.parse()?;
        }
    }
    let root = std::env::var("PACKCHAIN_DATA_DIR").unwrap_or_else(|_| "data".to_string());
    let analyzer = Analyzer::open(&root)?;
    analyzer.analyze(Budget::default(), "default")?;
    Ok(serve(addr, analyzer).await?)
}
