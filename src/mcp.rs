// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Jeremy Beker

//! MCP tool surface. Port of `server.py`.
//!
//! Tool names, argument names, descriptions, input schemas, response shapes,
//! and error message text are pinned by benchmarks/fixtures/python-v0.2.0/.
//! Like FastMCP, every failure — including authentication — surfaces as an
//! in-band tool error (`isError: true`) with text
//! `Error calling tool '<name>': <message>`, not a protocol-level error.
//!
//! Differences from Python, by design:
//! - No `MEMORY_TOKEN` env fallback: a Bearer Authorization header is required.
//! - Malformed item errors say e.g. "missing field `name`" instead of
//!   Python's bare KeyError text ("'name'").

use crate::graph::{Entity, FactInput, FactQuery, Relation};
use crate::store::{Store, StoreMap};
use crate::tokens::{TokenConfig, TokenEntry};
use http::request::Parts;
use rmcp::handler::server::common::Extension;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, ErrorCode, Implementation, JsonObject,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

pub const SERVER_NAME: &str = "Advanced Memory MCP";

const ERROR_UNAUTHORIZED: ErrorCode = ErrorCode(-32001);

pub struct AppState {
    pub stores: StoreMap,
    pub tokens: TokenConfig,
    pub aliases: HashMap<String, String>,
}

#[derive(Clone)]
pub struct MemoryServer {
    state: Arc<AppState>,
    tool_router: ToolRouter<Self>,
}

/// Internal operation error: a user-facing message string, or an I/O error
/// from persistence (required by `Store::mutate`'s bound).
#[derive(Debug)]
enum OpError {
    Msg(String),
    Io(std::io::Error),
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpError::Msg(m) => f.write_str(m),
            OpError::Io(e) => write!(f, "failed to persist graph: {e}"),
        }
    }
}

impl From<std::io::Error> for OpError {
    fn from(e: std::io::Error) -> Self {
        OpError::Io(e)
    }
}

impl From<String> for OpError {
    fn from(m: String) -> Self {
        OpError::Msg(m)
    }
}

/// FastMCP-compatible in-band tool error.
fn tool_error(tool: &str, msg: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![Content::text(format!(
        "Error calling tool '{tool}': {msg}"
    ))])
}

/// Wrap a tool body: Ok(value) becomes a structured result (compact JSON
/// text + structuredContent, matching FastMCP), Err becomes a tool error.
fn run(tool: &str, f: impl FnOnce() -> Result<Value, OpError>) -> CallToolResult {
    match f() {
        Ok(value) => CallToolResult::structured(value),
        Err(e) => tool_error(tool, e),
    }
}

/// Deserialize a list of loose JSON objects into typed items, stripping any
/// "type" discriminator a client might include (Python would let it clobber
/// the line type on disk and silently lose the row; we refuse to store it).
fn parse_items<T: serde::de::DeserializeOwned>(items: Vec<Value>) -> Result<Vec<T>, OpError> {
    items
        .into_iter()
        .map(|mut v| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("type");
            }
            serde_json::from_value(v).map_err(|e| OpError::Msg(e.to_string()))
        })
        .collect()
}

// ---- input schemas, copied verbatim from the Python server's tools/list ----

fn objects_param_schema(param: &str) -> JsonObject {
    rmcp::model::object(json!({
        "additionalProperties": false,
        "properties": {param: {"items": {"additionalProperties": true, "type": "object"}, "type": "array"}},
        "required": [param],
        "type": "object",
    }))
}

fn strings_param_schema(param: &str) -> JsonObject {
    rmcp::model::object(json!({
        "additionalProperties": false,
        "properties": {param: {"items": {"type": "string"}, "type": "array"}},
        "required": [param],
        "type": "object",
    }))
}

fn two_strings_schema(a: &str, b: &str) -> JsonObject {
    rmcp::model::object(json!({
        "additionalProperties": false,
        "properties": {a: {"type": "string"}, b: {"type": "string"}},
        "required": [a, b],
        "type": "object",
    }))
}

fn one_string_schema(a: &str) -> JsonObject {
    rmcp::model::object(json!({
        "additionalProperties": false,
        "properties": {a: {"type": "string"}},
        "required": [a],
        "type": "object",
    }))
}

fn search_facts_schema() -> JsonObject {
    rmcp::model::object(json!({
        "additionalProperties": false,
        "properties": {
            "query": {"type": "string", "description": "case-insensitive substring on fact text"},
            "entityName": {"type": "string", "description": "exact entity name filter"},
            "asOf": {"type": "string", "description": "facts valid at this instant (YYYY-MM-DD or ISO-8601)"},
            "since": {"type": "string", "description": "validFrom >= since"},
            "until": {"type": "string", "description": "validFrom <= until"},
            "includeSuperseded": {"type": "boolean", "description": "include facts whose validity ended (default false)"},
            "order": {"type": "string", "enum": ["desc", "asc"], "description": "validFrom ordering (default desc)"},
            "limit": {"type": "integer", "minimum": 1, "description": "max facts returned (default 20)"},
        },
        "type": "object",
    }))
}

fn no_params_schema() -> JsonObject {
    rmcp::model::object(json!({
        "additionalProperties": false,
        "properties": {},
        "type": "object",
    }))
}

fn output_schema() -> Arc<JsonObject> {
    Arc::new(rmcp::model::object(json!({
        "additionalProperties": true,
        "type": "object",
    })))
}

/// Behavioral hints advertised for each tool in tools/list. Per the MCP spec
/// these are advisory only (see ToolAnnotations) and clients must not make
/// security decisions from them. Every tool operates on a single user's local
/// knowledge graph, so all set openWorldHint=false. Read tools set
/// readOnlyHint=true; write tools declare whether they are destructive (remove
/// or overwrite existing data) and idempotent (a repeat with the same args
/// leaves the graph unchanged).
fn tool_annotations(name: &str) -> Option<ToolAnnotations> {
    // Read-only tool: never mutates the graph.
    let read = |title: &str| {
        ToolAnnotations::with_title(title)
            .read_only(true)
            .open_world(false)
    };
    // Write tool: declares destructive/idempotent explicitly.
    let write = |title: &str, destructive: bool, idempotent: bool| {
        ToolAnnotations::with_title(title)
            .read_only(false)
            .destructive(destructive)
            .idempotent(idempotent)
            .open_world(false)
    };
    Some(match name {
        // Additive writes: dedup by identity, so a replay is a no-op (idempotent)
        // and nothing existing is removed (non-destructive).
        "create_entities" => write("Create Entities", false, true),
        "create_relations" => write("Create Relations", false, true),
        "add_observations" => write("Add Observations", false, true),
        // Deletes remove data (destructive) but silently ignore already-absent
        // targets, so replaying reaches the same state (idempotent).
        "delete_entities" => write("Delete Entities", true, true),
        "delete_observations" => write("Delete Observations", true, true),
        "delete_relations" => write("Delete Relations", true, true),
        // Rename doesn't drop data, but a replay errors (source now gone), so
        // it is neither destructive nor idempotent.
        "rename_entity" => write("Rename Entity", false, false),
        // Merge removes the source entity (destructive) and a replay errors
        // (source gone), so it is not idempotent.
        "merge_entities" => write("Merge Entities", true, false),
        // Normalization rewrites types in place; a second run finds nothing left
        // to change (idempotent) and discards no data (non-destructive).
        "normalize_entity_types" => write("Normalize Entity Types", false, true),
        // Pure reads.
        "search_facts" => read("Search Facts"),
        "read_graph" => read("Read Graph"),
        "search_nodes" => read("Search Nodes"),
        "open_nodes" => read("Open Nodes"),
        _ => return None,
    })
}

// ---- typed parameter wrappers (deserialization only; schemas above) ----

#[derive(Deserialize)]
struct EntitiesParams {
    entities: Vec<Value>,
}

#[derive(Deserialize)]
struct RelationsParams {
    relations: Vec<Value>,
}

#[derive(Deserialize)]
struct ObservationsParams {
    observations: Vec<Value>,
}

#[derive(Deserialize)]
struct DeletionsParams {
    deletions: Vec<Value>,
}

#[derive(Deserialize)]
struct EntityNamesParams {
    #[serde(rename = "entityNames")]
    entity_names: Vec<String>,
}

#[derive(Deserialize)]
struct RenameParams {
    name: String,
    new_name: String,
}

#[derive(Deserialize)]
struct MergeParams {
    source: String,
    target: String,
}

#[derive(Deserialize)]
struct QueryParams {
    query: String,
}

#[derive(Deserialize)]
struct NamesParams {
    names: Vec<String>,
}

#[derive(Deserialize)]
struct ObservationInput {
    #[serde(rename = "entityName")]
    entity_name: String,
    contents: Vec<Value>,
}

/// Object form of a `contents` entry; plain strings are shorthand for
/// `{"text": ...}`. Unknown fields are carried onto the stored fact.
#[derive(Deserialize)]
struct FactInputObject {
    text: String,
    #[serde(rename = "validFrom", default)]
    valid_from: Option<String>,
    #[serde(rename = "validTo", default)]
    valid_to: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    supersedes: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

/// Validate a caller-supplied instant: date (YYYY-MM-DD) or ISO-8601
/// datetime. Lexicographic comparison over mixed-precision ISO strings is
/// what the engine relies on, so anything else is rejected loudly.
fn validate_instant(field: &str, value: &Option<String>) -> Result<(), OpError> {
    let Some(v) = value else { return Ok(()) };
    let ok = chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d").is_ok()
        || chrono::DateTime::parse_from_rfc3339(v).is_ok();
    if ok {
        Ok(())
    } else {
        Err(OpError::Msg(format!(
            "invalid {field} '{v}': use YYYY-MM-DD or ISO-8601 (e.g. 2026-05-01 or 2026-05-01T10:00:00+00:00)"
        )))
    }
}

fn parse_fact_inputs(contents: Vec<Value>) -> Result<Vec<FactInput>, OpError> {
    contents
        .into_iter()
        .map(|v| match v {
            Value::String(text) => Ok(FactInput::from_text(text)),
            obj @ Value::Object(_) => {
                let o: FactInputObject =
                    serde_json::from_value(obj).map_err(|e| OpError::Msg(e.to_string()))?;
                validate_instant("validFrom", &o.valid_from)?;
                validate_instant("validTo", &o.valid_to)?;
                Ok(FactInput {
                    text: o.text,
                    valid_from: o.valid_from,
                    valid_to: o.valid_to,
                    source: o.source,
                    supersedes: o.supersedes,
                    extra: o.extra,
                })
            }
            other => Err(OpError::Msg(format!(
                "observation contents must be strings or objects, got: {other}"
            ))),
        })
        .collect()
}

#[derive(Deserialize)]
struct SearchFactsParams {
    #[serde(default)]
    query: Option<String>,
    #[serde(rename = "entityName", default)]
    entity_name: Option<String>,
    #[serde(rename = "asOf", default)]
    as_of: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(rename = "includeSuperseded", default)]
    include_superseded: bool,
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    order: Option<String>,
}

#[derive(Deserialize)]
struct DeletionInput {
    #[serde(rename = "entityName")]
    entity_name: String,
    observations: Vec<String>,
}

#[derive(Deserialize)]
struct RelationTriple {
    from: String,
    to: String,
    #[serde(rename = "relationType")]
    relation_type: String,
}

#[tool_router]
impl MemoryServer {
    pub fn new(state: Arc<AppState>) -> Self {
        MemoryServer { state, tool_router: Self::tool_router() }
    }

    /// Resolve the Bearer token from the Authorization header. Messages
    /// match Python's `_get_token`; there is no env-var fallback.
    fn auth(&self, parts: &Parts) -> Result<&TokenEntry, OpError> {
        let header = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = if header.len() > 7 && header[..7].eq_ignore_ascii_case("bearer ") {
            &header[7..]
        } else {
            ""
        };
        if token.is_empty() {
            return Err(OpError::Msg(
                "No authentication token provided. Send a Bearer token in the Authorization header."
                    .to_string(),
            ));
        }
        self.state.tokens.get(token).map_err(OpError::Msg)
    }

    /// Authenticate and fetch the token's store; enforce write permission
    /// when `write` is set.
    fn authed_store(&self, parts: &Parts, write: bool) -> Result<Arc<Store>, OpError> {
        let entry = self.auth(parts)?;
        if write && entry.is_read_only() {
            return Err(OpError::Msg(
                "This token has read-only access. Write operations are not allowed.".to_string(),
            ));
        }
        self.state
            .stores
            .get(&entry.file)
            .map_err(|e| OpError::Msg(e.to_string()))
    }

    #[tool(
        description = "Create multiple new entities in the knowledge graph.\n\nEach entity should have 'name', 'entityType', and 'observations' fields.\nObservation entries may be plain strings or fact objects {text, validFrom,\nvalidTo, recordedAt, source}; they are stored as given (use add_observations\nfor write-time temporal defaults). Deduplicates by entity name - existing\nentities are skipped. New entities receive 'createdAt' and 'lastUpdated'\nISO 8601 UTC timestamps.",
        input_schema = objects_param_schema("entities")
    )]
    async fn create_entities(
        &self,
        Parameters(p): Parameters<EntitiesParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("create_entities", || {
            let store = self.authed_store(&parts, true)?;
            let entities: Vec<Entity> = parse_items(p.entities)?;
            let created =
                store.mutate(|g| Ok::<_, OpError>(g.create_entities(entities, &self.state.aliases)))?;
            Ok(json!({"created": created}))
        })
    }

    #[tool(
        description = "Create multiple new relations between entities.\n\nEach relation should have 'from', 'to', and 'relationType' fields.\nDeduplicates by the (from, to, relationType) tuple.\nNew relations receive 'createdAt' and 'lastUpdated' ISO 8601 UTC timestamps.",
        input_schema = objects_param_schema("relations")
    )]
    async fn create_relations(
        &self,
        Parameters(p): Parameters<RelationsParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("create_relations", || {
            let store = self.authed_store(&parts, true)?;
            let relations: Vec<Relation> = parse_items(p.relations)?;
            let created = store.mutate(|g| Ok::<_, OpError>(g.create_relations(relations)))?;
            Ok(json!({"created": created}))
        })
    }

    #[tool(
        description = "Add new observations (timestamped facts) to existing entities.\n\nEach observation has 'entityName' and 'contents': a list where each entry is\neither a plain string or an object {text, validFrom?, validTo?, source?,\nsupersedes?}. validFrom is when the fact became true in the world (e.g. the\nmeeting date, YYYY-MM-DD or ISO-8601) and defaults to write time; recordedAt\nis always set to write time. 'supersedes' names the exact text of an active\nfact on the same entity to close (its validTo becomes the new fact's\nvalidFrom) - it errors if the target is missing or already superseded.\nDeduplicates by text. Returns error if entity doesn't exist.",
        input_schema = objects_param_schema("observations")
    )]
    async fn add_observations(
        &self,
        Parameters(p): Parameters<ObservationsParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("add_observations", || {
            let store = self.authed_store(&parts, true)?;
            let inputs: Vec<ObservationInput> = parse_items(p.observations)?;
            let pairs = inputs
                .into_iter()
                .map(|o| Ok((o.entity_name, parse_fact_inputs(o.contents)?)))
                .collect::<Result<Vec<_>, OpError>>()?;
            let results = store.mutate(|g| g.add_observations(pairs).map_err(OpError::Msg))?;
            Ok(json!({"results": results}))
        })
    }

    #[tool(
        description = "Search observations as timestamped facts with temporal filters.\n\nAll parameters are optional and combine as AND filters:\n- query: case-insensitive substring matched against fact text\n- entityName: exact entity filter\n- asOf: return facts valid at that instant (validFrom <= asOf < validTo);\n  facts without validFrom count as always valid\n- since/until: window on validFrom; facts without validFrom are excluded\n- includeSuperseded: include facts whose validity ended (default false;\n  implied by asOf)\n- order: 'desc' (default, newest validFrom first) or 'asc' (history order);\n  facts without validFrom sort last\n- limit: max facts returned (default 20)\nDates are YYYY-MM-DD or ISO-8601; resolve relative times before calling.\nReturns {facts: [{entityName, text, validFrom, validTo, recordedAt,\nsource}], total} where total counts matches before the limit.",
        input_schema = search_facts_schema()
    )]
    async fn search_facts(
        &self,
        Parameters(p): Parameters<SearchFactsParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("search_facts", || {
            let store = self.authed_store(&parts, false)?;
            validate_instant("asOf", &p.as_of)?;
            validate_instant("since", &p.since)?;
            validate_instant("until", &p.until)?;
            let ascending = match p.order.as_deref() {
                None | Some("desc") => false,
                Some("asc") => true,
                Some(other) => {
                    return Err(OpError::Msg(format!(
                        "invalid order '{other}': use 'asc' or 'desc'"
                    )))
                }
            };
            let query = FactQuery {
                query: p.query,
                entity: p.entity_name,
                as_of: p.as_of,
                since: p.since,
                until: p.until,
                include_superseded: p.include_superseded,
                ascending,
                limit: p.limit.unwrap_or(20) as usize,
            };
            let (hits, total) = store.read(|g| g.search_facts(&query));
            let facts: Vec<Value> = hits
                .into_iter()
                .map(|(entity_name, fact)| {
                    let mut obj = serde_json::Map::new();
                    obj.insert("entityName".into(), Value::String(entity_name));
                    if let Value::Object(fields) =
                        serde_json::to_value(&fact).expect("fact serializes")
                    {
                        obj.extend(fields);
                    }
                    Value::Object(obj)
                })
                .collect();
            Ok(json!({"facts": facts, "total": total}))
        })
    }

    #[tool(
        description = "Delete entities and their associated relations from the knowledge graph.\n\nTakes a list of entity names to delete. Relations involving deleted entities\nare also removed (cascade delete).",
        input_schema = strings_param_schema("entityNames")
    )]
    async fn delete_entities(
        &self,
        Parameters(p): Parameters<EntityNamesParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("delete_entities", || {
            let store = self.authed_store(&parts, true)?;
            store.mutate(|g| {
                g.delete_entities(&p.entity_names);
                Ok::<_, OpError>(())
            })?;
            Ok(json!({"deleted": p.entity_names}))
        })
    }

    #[tool(
        description = "Delete specific observations from entities.\n\nEach deletion should have 'entityName' and 'observations' (list of exact\nfact texts to remove). Removes facts entirely regardless of temporal state;\nto close a fact while keeping history, supersede it via add_observations\ninstead. Silently ignores missing entities or observations.",
        input_schema = objects_param_schema("deletions")
    )]
    async fn delete_observations(
        &self,
        Parameters(p): Parameters<DeletionsParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("delete_observations", || {
            let store = self.authed_store(&parts, true)?;
            // Echo the raw deletions back like Python does.
            let echo = p.deletions.clone();
            let inputs: Vec<DeletionInput> = parse_items(p.deletions)?;
            let pairs = inputs
                .into_iter()
                .map(|d| (d.entity_name, d.observations))
                .collect();
            store.mutate(|g| {
                g.delete_observations(pairs);
                Ok::<_, OpError>(())
            })?;
            Ok(json!({"deleted": echo}))
        })
    }

    #[tool(
        description = "Delete specific relations from the knowledge graph.\n\nEach relation should have 'from', 'to', and 'relationType' fields.\nAll three fields must match for deletion.",
        input_schema = objects_param_schema("relations")
    )]
    async fn delete_relations(
        &self,
        Parameters(p): Parameters<RelationsParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("delete_relations", || {
            let store = self.authed_store(&parts, true)?;
            let echo = p.relations.clone();
            let triples: Vec<RelationTriple> = parse_items(p.relations)?;
            let keys = triples
                .into_iter()
                .map(|t| (t.from, t.to, t.relation_type))
                .collect();
            store.mutate(|g| {
                g.delete_relations(keys);
                Ok::<_, OpError>(())
            })?;
            Ok(json!({"deleted": echo}))
        })
    }

    #[tool(
        description = "Rename an entity in the knowledge graph.\n\nUpdates the entity's name and rewrites every relation that references it\n(both 'from' and 'to' endpoints). Errors if the source entity is not found,\nif an entity with 'new_name' already exists (use merge_entities to combine\nthem), or if name == new_name. Bumps lastUpdated on the entity and on every\ntouched relation. Returns {renamed: {from, to}, relationsUpdated: N}.",
        input_schema = two_strings_schema("name", "new_name")
    )]
    async fn rename_entity(
        &self,
        Parameters(p): Parameters<RenameParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("rename_entity", || {
            let store = self.authed_store(&parts, true)?;
            let result =
                store.mutate(|g| g.rename_entity(&p.name, &p.new_name).map_err(OpError::Msg))?;
            Ok(result)
        })
    }

    #[tool(
        description = "Merge the source entity into the target entity.\n\nThe source is removed; the target absorbs the source's observations\n(unioned, target order preserved) and relations (re-pointed, self-loops\ndropped, duplicates collapsed keeping the earliest createdAt). Target's\nentityType is kept; if source's entityType differed it is returned as\n'discardedType' in the response. createdAt becomes the earliest non-null\nof the two. Errors if either entity is missing or source == target.",
        input_schema = two_strings_schema("source", "target")
    )]
    async fn merge_entities(
        &self,
        Parameters(p): Parameters<MergeParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("merge_entities", || {
            let store = self.authed_store(&parts, true)?;
            let result =
                store.mutate(|g| g.merge_entities(&p.source, &p.target).map_err(OpError::Msg))?;
            Ok(result)
        })
    }

    #[tool(
        description = "Read the entire knowledge graph.\n\nReturns all entities and relations for the authenticated user.\nEntities include 'createdAt' and 'lastUpdated' timestamps (null for legacy\ndata); observations are fact objects {text, validFrom?, validTo?,\nrecordedAt?, source?}.",
        input_schema = no_params_schema()
    )]
    async fn read_graph(&self, Extension(parts): Extension<Parts>) -> CallToolResult {
        run("read_graph", || {
            let store = self.authed_store(&parts, false)?;
            Ok(store.read(|g| serde_json::to_value(g).expect("graph serializes")))
        })
    }

    #[tool(
        description = "Search for nodes in the knowledge graph.\n\nPerforms case-insensitive search across entity names, types, and observation\ntext. Returns matching entities (observations as fact objects) and any\nrelations where at least one endpoint matches. For fact-level temporal\nqueries (as-of, since/until, history) use search_facts instead.",
        input_schema = one_string_schema("query")
    )]
    async fn search_nodes(
        &self,
        Parameters(p): Parameters<QueryParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("search_nodes", || {
            let store = self.authed_store(&parts, false)?;
            Ok(store.read(|g| {
                serde_json::to_value(g.search_nodes(&p.query)).expect("graph serializes")
            }))
        })
    }

    #[tool(
        description = "Open specific nodes by name from the knowledge graph.\n\nReturns the requested entities (observations as fact objects, with\n'createdAt'/'lastUpdated' timestamps) and any relations where at least one\nendpoint is in the requested set.",
        input_schema = strings_param_schema("names")
    )]
    async fn open_nodes(
        &self,
        Parameters(p): Parameters<NamesParams>,
        Extension(parts): Extension<Parts>,
    ) -> CallToolResult {
        run("open_nodes", || {
            let store = self.authed_store(&parts, false)?;
            Ok(store.read(|g| {
                serde_json::to_value(g.open_nodes(&p.names)).expect("graph serializes")
            }))
        })
    }

    #[tool(
        description = "Normalize all entity types in the knowledge graph using configured aliases.\n\nApplies type alias mappings and Title Case normalization to all existing entities.\nReturns a summary of changes made. Read-only tokens are rejected.",
        input_schema = no_params_schema()
    )]
    async fn normalize_entity_types(&self, Extension(parts): Extension<Parts>) -> CallToolResult {
        run("normalize_entity_types", || {
            let store = self.authed_store(&parts, true)?;
            let changes = store.mutate(|g| {
                Ok::<_, OpError>(g.normalize_all_entity_types(&self.state.aliases))
            })?;
            let total = changes.len();
            Ok(json!({"changes": changes, "total": total}))
        })
    }
}

impl ServerHandler for MemoryServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.server_info = Implementation::from_build_env();
        info.server_info.name = SERVER_NAME.into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let parts = context.extensions.get::<Parts>().ok_or_else(|| {
            ErrorData::internal_error(
                "tools/list requires an HTTP request context (streamable HTTP transport)",
                None,
            )
        })?;
        self.auth(parts)
            .map_err(|e| ErrorData::new(ERROR_UNAUTHORIZED, e.to_string(), None))?;
        // The Python server advertises a permissive outputSchema on every
        // tool; the #[tool] macro can't set one, so add it (and behavioral
        // annotations) here.
        let mut tools: Vec<Tool> = self.tool_router.list_all();
        for tool in &mut tools {
            tool.output_schema = Some(output_schema());
            tool.annotations = tool_annotations(tool.name.as_ref());
        }
        Ok(ListToolsResult { tools, meta: None, next_cursor: None })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_router.get(name).cloned()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let tcc = ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }
}
