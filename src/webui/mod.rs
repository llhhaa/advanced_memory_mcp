// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jeremy Beker

//! Web UI: same routes and templates as the Python `webui` package, served
//! by the same binary as the MCP endpoint. Templates and static assets are
//! embedded at compile time (no filesystem access, no traversal surface).
//!
//! Handler helpers return `Result<_, Response>` so auth/permission gates can
//! short-circuit with the right status; the Err size lint isn't worth boxing
//! over in request-scoped code.
#![allow(clippy::result_large_err)]

pub mod auth;
mod api;
mod views;

use crate::mcp::AppState;
use crate::store::Store;
use auth::CurrentUser;
use axum::Router;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, patch, post};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::json;
use std::sync::Arc;

/// Percent-encode set for a single URL path segment. Like minijinja's
/// `urlencode` filter except `/` is encoded too , so entity names containing
/// slashes stay one path segment.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'.').remove(b'-').remove(b'_');

pub struct WebUi {
    pub state: Arc<AppState>,
    pub ui_secret: String,
    templates: minijinja::Environment<'static>,
}

const TEMPLATES: &[(&str, &str)] = &[
    ("base.html", include_str!("../../webui/templates/base.html")),
    ("login.html", include_str!("../../webui/templates/login.html")),
    ("entity_list.html", include_str!("../../webui/templates/entity_list.html")),
    ("entity_list_rows.html", include_str!("../../webui/templates/entity_list_rows.html")),
    ("entity_detail.html", include_str!("../../webui/templates/entity_detail.html")),
    ("observation_row.html", include_str!("../../webui/templates/observation_row.html")),
    ("graph.html", include_str!("../../webui/templates/graph.html")),
];

const STATIC_FILES: &[(&str, &str, &[u8])] = &[
    ("app.css", "text/css; charset=utf-8", include_bytes!("../../webui/static/app.css")),
    (
        "htmx.min.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../webui/static/htmx.min.js"),
    ),
    (
        "cytoscape.min.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../webui/static/cytoscape.min.js"),
    ),
];

impl WebUi {
    pub fn new(state: Arc<AppState>, ui_secret: String) -> Self {
        let mut templates = minijinja::Environment::new();
        templates.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
        // Render just the date part of a fact timestamp (validFrom may be a
        // bare date or a full ISO instant).
        templates.add_filter("datepart", |value: String| {
            value.chars().take(10).collect::<String>()
        });
        templates.add_filter("pathsegment", |value: String| {
            utf8_percent_encode(&value, PATH_SEGMENT).to_string()
        });
        for (name, source) in TEMPLATES {
            templates
                .add_template(name, source)
                .expect("embedded template parses");
        }
        WebUi { state, ui_secret, templates }
    }

    /// Resolve the user's store, mapping a load failure to a 500.
    fn store_for(&self, user: &CurrentUser) -> Result<Arc<Store>, Response> {
        self.state.stores.get(&user.entry.file).map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        })
    }
}

fn render(ui: &WebUi, name: &str, ctx: minijinja::Value) -> String {
    ui.templates
        .get_template(name)
        .expect("template registered")
        .render(ctx)
        .expect("template renders")
}

fn html(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

/// HTML auth gate: resolve the session or redirect to the login page with a
/// safe `next` target. Port of `login_required_html`.
fn current_user_or_login_redirect(
    ui: &WebUi,
    headers: &HeaderMap,
    path: &str,
    query: Option<&str>,
) -> Result<CurrentUser, Response> {
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    match auth::resolve_session(cookie, &ui.ui_secret, &ui.state.tokens) {
        Some(user) => Ok(user),
        None => {
            let mut next = path.to_string();
            if let Some(q) = query {
                next = format!("{next}?{q}");
            }
            let location = format!(
                "/ui/login?next={}",
                utf8_percent_encode(&next, NON_ALPHANUMERIC)
            );
            Err((
                StatusCode::SEE_OTHER,
                [(header::LOCATION, location)],
            )
                .into_response())
        }
    }
}

/// JSON auth gate: 401 like Python's `login_required_api`.
fn current_user_or_401(ui: &WebUi, headers: &HeaderMap) -> Result<CurrentUser, Response> {
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    auth::resolve_session(cookie, &ui.ui_secret, &ui.state.tokens).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
    })
}

/// Redirect the bare site root to the UI so users don't have to remember the
/// `/ui/` subpath; they land on the login page (or list, if authenticated).
async fn root_redirect() -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, "/ui/")]).into_response()
}

async fn serve_static(Path(path): Path<String>) -> Response {
    for (name, content_type, bytes) in STATIC_FILES {
        if *name == path {
            return ([(header::CONTENT_TYPE, *content_type)], *bytes).into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

/// Build the /ui router. Mounted alongside /mcp in main.rs.
pub fn router(state: Arc<AppState>, ui_secret: String) -> Router {
    let ui = Arc::new(WebUi::new(state, ui_secret));
    Router::new()
        .route("/", get(root_redirect))
        .route("/ui/login", get(views::login_get).post(views::login_post))
        .route("/ui/logout", post(views::logout))
        .route("/ui/", get(views::entity_list))
        .route("/ui/search", get(views::entity_list_rows))
        .route("/ui/entity/{*name}", get(views::entity_detail))
        .route("/ui/graph", get(views::graph_page))
        .route("/ui/api/graph", get(api::graph_data))
        .route("/ui/api/observations", patch(api::update_observation))
        .route("/ui/api/observations/delete", post(api::delete_observation))
        .route("/ui/api/entities/{*name}", delete(api::delete_entity))
        .route("/ui/static/{*path}", get(serve_static))
        .with_state(ui)
}
