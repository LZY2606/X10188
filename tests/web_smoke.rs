mod common;
use common::*;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use microscope::git::{git_oid, Kind};
use microscope::web::router;
use tower::ServiceExt;

fn multipart(name: &str, filename: &str, bytes: &[u8]) -> Body {
    let boundary = "----microscopetest";
    let mut data = Vec::new();
    data.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    data.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n").as_bytes(),
    );
    data.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    data.extend_from_slice(bytes);
    data.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Body::from(data)
}

fn ct(boundary: &str) -> String {
    format!("multipart/form-data; boundary={boundary}")
}

#[tokio::test]
async fn home_shows_title_and_api_roundtrips() {
    let app_state = std::sync::Arc::new(temp_app("web"));
    let app = router(app_state.clone());

    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(html.contains("包链显微镜"), "home must show title");

    // import via JSON api
    let content = b"web upload blob body".to_vec();
    let built = build_pack(&[PackObj::Full(Kind::Blob, content.clone())]);
    let body = multipart("file", "up.pack", &built.bytes);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/import")
                .header("content-type", ct("----microscopetest"))
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["ok"], true);

    // objects api reports ok with recomputed oid
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/api/objects").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v[0]["status"], "ok");
    assert_eq!(v[0]["actual_oid"], serde_json::json!(git_oid(Kind::Blob, &content)));

    // layout api exposes fanout/zlib boundary info after idx import
    let body = multipart("file", "up.idx", &built.idx);
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/import")
                .header("content-type", ct("----microscopetest"))
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/api/layout/1").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["fanout"].as_array().unwrap().len(), 256);
    assert!(v["entries"][0]["z_len"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn delete_shows_dependents_then_recomputes() {
    let app_state = std::sync::Arc::new(temp_app("webdel"));
    let app = router(app_state.clone());

    // loose base + pack consumer
    let base = b"deletion base payload!".to_vec();
    let base_oid = git_oid(Kind::Blob, &base);
    let d = encode_delta(
        base.len(),
        &[
            DeltaOp::Copy(0, base.len()),
            DeltaOp::Insert(b"!".to_vec()),
        ],
    );
    let mut result = base.clone();
    result.push(b'!');
    let consumer = build_pack(&[PackObj::Ref {
        base_oid: base_oid.clone(),
        delta: d,
        result: (Kind::Blob, result),
    }]);

    // import loose
    let loose = loose_object(Kind::Blob, &base);
    let body = multipart("file", &format!("{base_oid}"), &loose);
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/import")
                .header("content-type", ct("----microscopetest"))
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    // import pack
    let body = multipart("file", "c.pack", &consumer.bytes);
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/import")
                .header("content-type", ct("----microscopetest"))
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();

    // loose source id should be 1; check dependents lists the delta consumer
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/sources/1/dependents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v.as_array().unwrap().iter().any(|d| d["kind"] == "ref-delta" || d["entry_id"] == 2));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/sources/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // consumer now missing its base
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/api/objects?status=error").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v.as_array().unwrap().iter().any(|o| o["error"]["MissingBase"].as_str().is_some()));
}
