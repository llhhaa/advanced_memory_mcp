// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jeremy Beker

//! /mcp endpoint authentication tests: tools/list requires a Bearer token
//! (like every other request, per the README), and authentication failures
//! there surface as JSON-RPC protocol errors rather than tool metadata.

use advanced_memory_mcp::mcp::{AppState, MemoryServer};
use advanced_memory_mcp::store::StoreMap;
use advanced_memory_mcp::tokens::TokenConfig;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, header};
use http_body_util::BodyExt;
use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

const RW_TOKEN: &str = "alice_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RO_TOKEN: &str = "bob_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TOOLS: usize = 13;

fn mcp_app() -> (Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
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

    // Mirror main.rs's deployment settings; json_response collapses the
    // POST reply (usually an SSE stream) into a single JSON body that the
    // tests can assert on directly (allowed by the spec, 2025-06-18).
    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true);
    let service = StreamableHttpService::new(
        move || Ok(MemoryServer::new(state.clone())),
        LocalSessionManager::default().into(),
        config,
    );
    (Router::new().nest_service("/mcp", service), dir)
}

/// POST a JSON-RPC request to /mcp, optionally with a Bearer token.
async fn post(body: &str, token: Option<&str>) -> (u16, Value) {
    let (app, _dir) = mcp_app();
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-06-18");
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let response = app.oneshot(builder.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("non-JSON response ({status}): {e}: {}", String::from_utf8_lossy(&bytes)));
    (status, json)
}

fn tools_list_body() -> String {
    serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string()
}

fn initialize_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.0.0"},
        },
    })
    .to_string()
}

#[tokio::test]
async fn tools_list_without_token_is_a_protocol_error() {
    let (status, body) = post(&tools_list_body(), None).await;
    let err = body["error"].as_object().expect("expected a JSON-RPC error");
    assert_eq!(err["code"], -32001);
    assert!(err["message"].as_str().unwrap().contains("No authentication token provided"));
    assert_eq!(status, 200); // in-band JSON-RPC error body, standard for streamable HTTP
    assert!(body["result"].is_null()); // no tool metadata leaks
}

#[tokio::test]
async fn tools_list_with_bad_token_is_a_protocol_error() {
    let (_, body) = post(&tools_list_body(), Some("not_a_real_token")).await;
    let err = body["error"].as_object().expect("expected a JSON-RPC error");
    assert_eq!(err["code"], -32001);
    assert!(err["message"].as_str().unwrap().contains("Unknown or invalid authentication token"));
}

#[tokio::test]
async fn tools_list_with_rw_token_lists_all_tools() {
    let (_, body) = post(&tools_list_body(), Some(RW_TOKEN)).await;
    let tools = body["result"]["tools"].as_array().expect("expected result.tools");
    assert_eq!(tools.len(), TOOLS);
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"search_nodes"));
    assert!(names.contains(&"search_facts"));
}

#[tokio::test]
async fn tools_list_with_ro_token_lists_all_tools() {
    // Metadata is read-only; a read-only token must see the tool surface.
    let (_, body) = post(&tools_list_body(), Some(RO_TOKEN)).await;
    assert!(body["error"].is_null(), "unexpected error: {body}");
    assert_eq!(body["result"]["tools"].as_array().unwrap().len(), TOOLS);
}

#[tokio::test]
async fn initialize_without_token_still_works() {
    // Deliberate scope: initialize carries no tool metadata and is the
    // client's first call, so it stays reachable without a token.
    let (_, body) = post(&initialize_body(), None).await;
    assert!(body["error"].is_null(), "unexpected error: {body}");
    assert_eq!(body["result"]["serverInfo"]["name"], "Advanced Memory MCP");
}

#[tokio::test]
async fn tools_call_without_token_is_still_an_in_band_error() {
    // The existing tool-layer convention (documented at the top of
    // src/mcp.rs) is unchanged: tool calls report failures in-band.
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "search_nodes", "arguments": {"query": "x"}},
    })
    .to_string();
    let (_, body) = post(&body, None).await;
    let result = &body["result"];
    assert_eq!(result["isError"], true);
    assert!(result["content"][0]["text"]
        .as_str()
        .unwrap()
        .starts_with("Error calling tool 'search_nodes': No authentication token provided"));
    // The tool list itself must NOT be disclosed here.
    assert!(!serde_json::to_string(&body).unwrap().contains("open_nodes"));
}
