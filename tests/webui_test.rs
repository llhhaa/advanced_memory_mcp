// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jeremy Beker

//! Web UI integration tests. Port of the Python tests/ suite semantics:
//! test_auth.py, test_views.py, test_mutations.py, test_graph_api.py,
//! test_entity_detail.py, test_static.py.

use advanced_memory_mcp::mcp::AppState;
use advanced_memory_mcp::store::StoreMap;
use advanced_memory_mcp::tokens::TokenConfig;
use advanced_memory_mcp::webui::{auth, router};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

const RW_TOKEN: &str = "alice_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RO_TOKEN: &str = "bob_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const UI_SECRET: &str = "test-secret-not-for-production";

const SAMPLE_DATA: &str = concat!(
    "{\"type\": \"entity\", \"name\": \"Alice\", \"entityType\": \"Person\", \"observations\": [\"Likes coffee\", \"Lives in Boston\", {\"text\": \"old role: IC\", \"validFrom\": \"2025-06-01\", \"validTo\": \"2026-01-15\"}, {\"text\": \"new role: manager\", \"validFrom\": \"2026-01-15\"}], \"createdAt\": \"2026-01-01T00:00:00+00:00\", \"lastUpdated\": \"2026-01-02T00:00:00+00:00\"}\n",
    "{\"type\": \"entity\", \"name\": \"Bob\", \"entityType\": \"Person\", \"observations\": [\"Plays chess\"], \"createdAt\": null, \"lastUpdated\": null}\n",
    "{\"type\": \"entity\", \"name\": \"Project X\", \"entityType\": \"Project\", \"observations\": [], \"createdAt\": null, \"lastUpdated\": null}\n",
    "{\"type\": \"relation\", \"from\": \"Alice\", \"to\": \"Project X\", \"relationType\": \"worksOn\", \"createdAt\": null, \"lastUpdated\": null}\n",
    "{\"type\": \"relation\", \"from\": \"Bob\", \"to\": \"Alice\", \"relationType\": \"knows\", \"createdAt\": null, \"lastUpdated\": null}\n",
);

/// Fixture with an entity whose name contains a slash (e.g. a GitHub
/// `owner/repo` handle), plus a relation pointing at it from `Alice`.
const SLASH_DATA: &str = concat!(
    "{\"type\": \"entity\", \"name\": \"llhhaa/advanced_memory_mcp\", \"entityType\": \"Project\", \"observations\": [\"Rust rewrite\"], \"createdAt\": null, \"lastUpdated\": null}\n",
    "{\"type\": \"entity\", \"name\": \"Alice\", \"entityType\": \"Person\", \"observations\": [], \"createdAt\": null, \"lastUpdated\": null}\n",
    "{\"type\": \"relation\", \"from\": \"Alice\", \"to\": \"llhhaa/advanced_memory_mcp\", \"relationType\": \"co-maintains\", \"createdAt\": null, \"lastUpdated\": null}\n",
);

struct TestApp {
    app: Router,
    _dir: tempfile::TempDir,
}

fn test_app() -> TestApp {
    test_app_with(SAMPLE_DATA)
}

fn test_app_with(data: &str) -> TestApp {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("alice.jsonl"), data).unwrap();
    let tokens_path = dir.path().join("tokens.json");
    std::fs::write(
        &tokens_path,
        format!(
            r#"{{"{RW_TOKEN}": {{"file": "alice.jsonl", "mode": "read-write"}},
                 "{RO_TOKEN}": {{"file": "alice.jsonl", "mode": "read-only"}}}}"#
        ),
    )
    .unwrap();

    let state = Arc::new(AppState {
        stores: StoreMap::new(dir.path().to_path_buf()),
        tokens: TokenConfig::load(&tokens_path).unwrap(),
        aliases: HashMap::new(),
    });
    TestApp { app: router(state, UI_SECRET.to_string()), _dir: dir }
}

fn session_cookie(token: &str) -> String {
    let value = auth::sign_session(UI_SECRET, token, chrono::Utc::now().timestamp());
    format!("{}={}", auth::COOKIE_NAME, value)
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).to_string())
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri(path);
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    builder.body(Body::empty()).unwrap()
}

fn json_req(method: &str, path: &str, cookie: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

// ---- auth (test_auth.py) ----

#[tokio::test]
async fn unauthenticated_html_redirects_to_login_with_next() {
    let t = test_app();
    let (status, headers, _) = send(&t.app, get("/ui/", None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with("/ui/login?next="), "got {location}");
}

#[tokio::test]
async fn unauthenticated_api_gets_401() {
    let t = test_app();
    let (status, _, body) = send(&t.app, get("/ui/api/graph", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("unauthorized"));
}

#[tokio::test]
async fn login_with_invalid_token_shows_error() {
    let t = test_app();
    let req = Request::builder()
        .method("POST")
        .uri("/ui/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("token=wrong"))
        .unwrap();
    let (status, _, body) = send(&t.app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Invalid token."));
}

#[tokio::test]
async fn login_with_valid_token_sets_cookie_and_redirects() {
    let t = test_app();
    let req = Request::builder()
        .method("POST")
        .uri("/ui/login?next=%2Fui%2Fentity%2FAlice")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("token={RW_TOKEN}")))
        .unwrap();
    let (status, headers, _) = send(&t.app, req).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/ui/entity/Alice");
    let cookie = headers[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with(&format!("{}=", auth::COOKIE_NAME)));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Path=/ui"));
}

#[tokio::test]
async fn offsite_next_is_replaced() {
    let t = test_app();
    let req = Request::builder()
        .method("POST")
        .uri("/ui/login?next=https%3A%2F%2Fevil.example%2F")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("token={RW_TOKEN}")))
        .unwrap();
    let (_, headers, _) = send(&t.app, req).await;
    assert_eq!(headers[header::LOCATION], "/ui/");
}

#[tokio::test]
async fn tampered_cookie_is_rejected() {
    let t = test_app();
    // Flip the final signature character to a different base64url symbol so
    // the cookie is always altered regardless of its random content.
    let cookie = session_cookie(RW_TOKEN);
    let last = cookie.chars().last().unwrap();
    let flipped = if last == 'A' { 'B' } else { 'A' };
    let mut tampered = cookie;
    tampered.pop();
    tampered.push(flipped);
    let (status, _, _) = send(&t.app, get("/ui/", Some(&tampered))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn logout_clears_cookie() {
    let t = test_app();
    let req = Request::builder()
        .method("POST")
        .uri("/ui/logout")
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = send(&t.app, req).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/ui/login");
    assert!(headers[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
}

// ---- views (test_views.py, test_entity_detail.py) ----

#[tokio::test]
async fn entity_list_renders_sorted_with_user_chip() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (status, _, body) = send(&t.app, get("/ui/", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Alice"));
    assert!(body.contains("Project X"));
    assert!(body.contains("alice")); // user chip label
    assert!(!body.contains("read-only"));
    // sorted: Alice before Bob before Project X
    let a = body.find(">Alice<").unwrap();
    let b = body.find(">Bob<").unwrap();
    assert!(a < b);
}

#[tokio::test]
async fn read_only_token_sees_read_only_chip() {
    let t = test_app();
    let cookie = session_cookie(RO_TOKEN);
    let (_, _, body) = send(&t.app, get("/ui/", Some(&cookie))).await;
    assert!(body.contains("read-only"));
}

#[tokio::test]
async fn search_filters_rows() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (_, _, body) = send(&t.app, get("/ui/search?q=coffee", Some(&cookie))).await;
    assert!(body.contains("Alice"));
    assert!(!body.contains("Bob"));

    let (_, _, body) = send(&t.app, get("/ui/search?type=Project", Some(&cookie))).await;
    assert!(body.contains("Project X"));
    assert!(!body.contains("Alice"));

    let (_, _, body) = send(&t.app, get("/ui/search?q=zzz", Some(&cookie))).await;
    assert!(body.contains("No entities match."));
}

#[tokio::test]
async fn root_redirects_to_ui() {
    let t = test_app();
    let (status, headers, _) = send(&t.app, get("/", None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/ui/");
}

#[tokio::test]
async fn search_sorts_by_column() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);

    // Descending name: Project X before Bob before Alice (reverse of default).
    let (_, _, body) = send(&t.app, get("/ui/search?sort=name&dir=desc", Some(&cookie))).await;
    let a = body.find(">Alice<").unwrap();
    let b = body.find(">Bob<").unwrap();
    assert!(b < a, "desc name should put Bob before Alice");

    // Ascending name (explicit) matches the default order.
    let (_, _, body) = send(&t.app, get("/ui/search?sort=name&dir=asc", Some(&cookie))).await;
    let a = body.find(">Alice<").unwrap();
    let b = body.find(">Bob<").unwrap();
    assert!(a < b, "asc name should put Alice before Bob");
}

#[tokio::test]
async fn entity_detail_splits_relations() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (status, _, body) = send(&t.app, get("/ui/entity/Alice", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Likes coffee"));
    assert!(body.contains("worksOn")); // outgoing
    assert!(body.contains("knows")); // incoming from Bob
}

#[tokio::test]
async fn entity_detail_shows_temporal_badges_active_first() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (_, _, body) = send(&t.app, get("/ui/entity/Alice", Some(&cookie))).await;
    // Superseded fact gets a badge and the date chip shows the date part.
    assert!(body.contains("old role: IC"));
    assert!(body.contains("badge-superseded"));
    assert!(body.contains("2026-01-15"));
    // Active facts render before superseded ones.
    let active = body.find("new role: manager").unwrap();
    let superseded = body.find("old role: IC").unwrap();
    assert!(active < superseded);
    // Legacy (string) facts render their text without badges.
    assert!(body.contains("Likes coffee"));
}

#[tokio::test]
async fn search_matches_temporal_fact_text() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (_, _, body) = send(&t.app, get("/ui/search?q=manager", Some(&cookie))).await;
    assert!(body.contains("Alice"));
}

#[tokio::test]
async fn entity_detail_404_for_missing() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (status, _, _) = send(&t.app, get("/ui/entity/Nobody", Some(&cookie))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn entity_detail_navigable_with_slash_in_name() {
    let t = test_app_with(SLASH_DATA);
    let cookie = session_cookie(RW_TOKEN);

    // The raw (unencoded) form reported as a 404 must resolve.
    let (status, _, body) = send(
        &t.app,
        get("/ui/entity/llhhaa/advanced_memory_mcp", Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Rust rewrite"));

    // The percent-encoded form (what the templates and graph JS emit) too.
    let (status, _, _) = send(
        &t.app,
        get("/ui/entity/llhhaa%2Fadvanced_memory_mcp", Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The list links to the slash entity as a single, encoded segment.
    let (_, _, list) = send(&t.app, get("/ui/", Some(&cookie))).await;
    assert!(list.contains("/ui/entity/llhhaa%2Fadvanced_memory_mcp"), "got {list}");
}

#[tokio::test]
async fn delete_entity_with_slash_in_name() {
    let t = test_app_with(SLASH_DATA);
    let cookie = session_cookie(RW_TOKEN);
    let (status, headers, _) = send(
        &t.app,
        json_req("DELETE", "/ui/api/entities/llhhaa/advanced_memory_mcp", Some(&cookie), ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["HX-Redirect"], "/ui/");

    let (status, _, _) = send(
        &t.app,
        get("/ui/entity/llhhaa/advanced_memory_mcp", Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn graph_page_renders_and_404s_on_bad_center() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (status, _, body) = send(&t.app, get("/ui/graph", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Full graph"));
    assert!(body.contains("api/graph?all=1"));

    let (status, _, body) =
        send(&t.app, get("/ui/graph?center=Alice&depth=3", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("center=Alice&amp;depth=3") || body.contains("center=Alice&depth=3"));

    let (status, _, _) = send(&t.app, get("/ui/graph?center=Nobody", Some(&cookie))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---- graph API (test_graph_api.py) ----

#[tokio::test]
async fn graph_data_full_shape() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (status, _, body) = send(&t.app, get("/ui/api/graph", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(data["count"], 3);
    assert_eq!(data["nodes"].as_array().unwrap().len(), 3);
    assert_eq!(data["edges"].as_array().unwrap().len(), 2);
    assert_eq!(data["edges"][0]["data"]["id"], "Alice|worksOn|Project X");
}

#[tokio::test]
async fn graph_data_center_bfs_depth() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    // Depth 1 from Project X: Alice (direct), not Bob (2 hops).
    let (_, _, body) = send(
        &t.app,
        get("/ui/api/graph?center=Project%20X&depth=1", Some(&cookie)),
    )
    .await;
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(data["count"], 2);

    let (_, _, body) = send(
        &t.app,
        get("/ui/api/graph?center=Project%20X&depth=2", Some(&cookie)),
    )
    .await;
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(data["count"], 3);

    // Bad depth string falls back to 2.
    let (_, _, body) = send(
        &t.app,
        get("/ui/api/graph?center=Project%20X&depth=banana", Some(&cookie)),
    )
    .await;
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(data["count"], 3);

    let (status, _, _) = send(
        &t.app,
        get("/ui/api/graph?center=Nobody", Some(&cookie)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---- mutations (test_mutations.py) ----

#[tokio::test]
async fn read_only_token_gets_403_on_mutations() {
    let t = test_app();
    let cookie = session_cookie(RO_TOKEN);
    let cases = [
        json_req(
            "PATCH",
            "/ui/api/observations",
            Some(&cookie),
            r#"{"entity": "Alice", "original_text": "Likes coffee", "new_text": "x"}"#,
        ),
        json_req(
            "POST",
            "/ui/api/observations/delete",
            Some(&cookie),
            r#"{"entity": "Alice", "text": "Likes coffee"}"#,
        ),
        json_req("DELETE", "/ui/api/entities/Alice", Some(&cookie), ""),
    ];
    for req in cases {
        let (status, _, _) = send(&t.app, req).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn update_observation_returns_row_fragment() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (status, _, body) = send(
        &t.app,
        json_req(
            "PATCH",
            "/ui/api/observations",
            Some(&cookie),
            r#"{"entity": "Alice", "original_text": "Likes coffee", "new_text": "Likes tea"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Likes tea"));
    assert!(body.contains("obs-text"));

    // 404 when the original text doesn't exist.
    let (status, _, _) = send(
        &t.app,
        json_req(
            "PATCH",
            "/ui/api/observations",
            Some(&cookie),
            r#"{"entity": "Alice", "original_text": "nope", "new_text": "x"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_observation_returns_empty_fragment() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (status, _, body) = send(
        &t.app,
        json_req(
            "POST",
            "/ui/api/observations/delete",
            Some(&cookie),
            r#"{"entity": "Alice", "text": "Likes coffee"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());

    let (_, _, detail) = send(&t.app, get("/ui/entity/Alice", Some(&cookie))).await;
    assert!(!detail.contains("Likes coffee"));
}

#[tokio::test]
async fn delete_entity_redirects_and_cascades() {
    let t = test_app();
    let cookie = session_cookie(RW_TOKEN);
    let (status, headers, _) = send(
        &t.app,
        json_req("DELETE", "/ui/api/entities/Alice", Some(&cookie), ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["HX-Redirect"], "/ui/");

    let (status, _, _) = send(&t.app, get("/ui/entity/Alice", Some(&cookie))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Cascade removed Bob->Alice relation from graph data.
    let (_, _, body) = send(&t.app, get("/ui/api/graph", Some(&cookie))).await;
    let data: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(data["edges"].as_array().unwrap().len(), 0);

    let (status, _, _) = send(
        &t.app,
        json_req("DELETE", "/ui/api/entities/Alice", Some(&cookie), ""),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---- static (test_static.py) ----

#[tokio::test]
async fn static_files_served_with_types() {
    let t = test_app();
    let (status, headers, _) = send(&t.app, get("/ui/static/app.css", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[header::CONTENT_TYPE].to_str().unwrap().contains("text/css"));

    let (status, _, _) = send(&t.app, get("/ui/static/htmx.min.js", None)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = send(&t.app, get("/ui/static/nope.js", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Traversal can't reach the filesystem (assets are embedded), but the
    // route should still 404 cleanly.
    let (status, _, _) = send(&t.app, get("/ui/static/../../etc/passwd", None)).await;
    assert_ne!(status, StatusCode::OK);
}
