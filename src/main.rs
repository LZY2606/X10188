use packchain::engine::Budget;
use packchain::server;
use std::path::PathBuf;

fn main() {
    let mut addr = "127.0.0.1:5248".to_string();
    let mut data_dir = PathBuf::from("packchain_data");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => {
                addr = args.next().expect("--addr requires a value");
            }
            "--data-dir" => {
                data_dir = PathBuf::from(args.next().expect("--data-dir requires a value"));
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        if let Err(e) = server::serve(&addr, data_dir, Budget::default()).await {
            eprintln!("server error: {e}");
            std::process::exit(1);
        }
    });
}
