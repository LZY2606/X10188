use std::net::SocketAddr;
use std::sync::Arc;

use pack_chain_microscope::web::router;
use pack_chain_microscope::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut addr: SocketAddr = "127.0.0.1:5248".parse()?;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" | "-a" => {
                addr = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--addr requires a value"))?
                    .parse()?;
            }
            "--data-dir" | "-d" => {
                let dir = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--data-dir requires a value"))?;
                std::env::set_var("PCM_DATA_DIR", dir);
            }
            other => {
                return Err(anyhow::anyhow!("unknown argument {other}"));
            }
        }
    }

    let data_dir = std::env::var("PCM_DATA_DIR")
        .unwrap_or_else(|_| "data".to_string());
    let store = Arc::new(Store::open(std::path::Path::new(&data_dir))?);
    let app = router(store);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("包链显微镜 listening on http://{addr} (data dir: {data_dir})");
    axum::serve(listener, app).await?;
    Ok(())
}
