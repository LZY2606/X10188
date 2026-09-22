use pack_chain_microscope::git::*;
use pack_chain_microscope::pack::{build_pack, SynEntry};
use std::sync::Arc;

fn multipart(name: &str, filename: &str, bytes: &[u8]) -> reqwest::multipart::Form {
    reqwest::multipart::Form::new().part(
        name.to_string(),
        reqwest::multipart::Part::bytes(bytes.to_vec())
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .unwrap(),
    )
}

#[tokio::test]
async fn server_serves_ui_and_ingests_pack() {
    let dir = std::env::temp_dir().join(format!(
        "pcsm-http-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = pack_chain_microscope::db::Db::open(dir.join("h.sqlite").to_str().unwrap()).unwrap();
    let state = Arc::new(pack_chain_microscope::api::AppState {
        db,
        data_dir: dir,
    });
    let app = pack_chain_microscope::api::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");

    let html = reqwest::get(format!("{base}/")).await.unwrap().text().await.unwrap();
    assert!(html.contains("包链显微镜"), "title missing from page");

    // Build and upload a real small pack.
    let v0 = b"http smoke base content 000011112222".to_vec();
    let v1 = b"http smoke BASE content 000011112222!".to_vec();
    let d = pack_chain_microscope::delta::delta_from_copy_insert(&v0, &v1);
    let pack = build_pack(
        &[
            SynEntry::Full { kind: OBJ_BLOB, content: v0.clone() },
            SynEntry::OfsDelta { base_index: 0, delta: d },
        ],
        &Default::default(),
    );
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/sources"))
        .multipart(multipart("files", "smoke.pack", &pack.bytes))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["summary"]["resolved"], 2);

    let nodes: serde_json::Value = reqwest::get(format!("{base}/api/nodes"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(nodes["nodes"].as_array().unwrap().len(), 2);

    // Branch create + listing.
    let br: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/api/branches"))
        .json(&serde_json::json!({"name":"probe"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(br["id"].as_i64().is_some());

    // Budget endpoint round trip.
    reqwest::Client::new()
        .post(format!("{base}/api/budgets"))
        .json(&serde_json::json!({"total_bytes": 123456}))
        .send()
        .await
        .unwrap();
    let bg: serde_json::Value = reqwest::get(format!("{base}/api/budgets"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bg["total_bytes"], 123456);

    // Detail of the delta node carries provenance steps.
    let delta_node = nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["kind"] == "ofs-delta")
        .unwrap();
    let nid = delta_node["id"].as_i64().unwrap();
    let detail: serde_json::Value = reqwest::get(format!("{base}/api/nodes/{nid}/1"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(detail["delta_steps"].as_array().unwrap().len() >= 2);
    assert_eq!(detail["resolved_oid"], to_hex(&git_object_id(OBJ_BLOB, &v1)));
}
