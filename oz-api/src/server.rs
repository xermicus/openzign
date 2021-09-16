use crate::{core, Opt};
use async_std::{
    sync::{Arc, Mutex},
    task::spawn_blocking,
};
use once_cell::sync::OnceCell;
use oz_indexer::{index::open_index, schema::*};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::HashMap, path::PathBuf};
use tantivy::{query::QueryParser, schema::NamedFieldDocument, Index, IndexReader};
use tide::{prelude::*, Request};

static FACET_INFO: OnceCell<Mutex<HashMap<IndexKind, HashMap<String, u64>>>> = OnceCell::new();

#[derive(Clone)]
pub struct Context {
    pub artifact_index: Arc<Index>,
    pub artifact_index_reader: Arc<IndexReader>,
    pub zignature_index: Arc<Index>,
    pub zignature_index_reader: Arc<IndexReader>,
    pub block_index: Arc<Index>,
    pub block_index_reader: Arc<IndexReader>,
}

impl Context {
    fn new(index_dir: PathBuf) -> Self {
        let index_dir = Some(index_dir);
        let schemas = Schemas::default();
        let artifact_index = Arc::new(
            open_index(index_dir.clone(), SchemaKind::Artifact(schemas.artifact)).unwrap(),
        );
        let artifact_index_reader = Arc::new(artifact_index.reader().unwrap());
        let zignature_index = Arc::new(
            open_index(index_dir.clone(), SchemaKind::Zignature(schemas.zignature)).unwrap(),
        );
        let zignature_index_reader = Arc::new(zignature_index.reader().unwrap());
        let block_index =
            Arc::new(open_index(index_dir, SchemaKind::Block(schemas.block)).unwrap());
        let block_index_reader = Arc::new(block_index.reader().unwrap());
        Context {
            artifact_index,
            artifact_index_reader,
            zignature_index,
            zignature_index_reader,
            block_index,
            block_index_reader,
        }
    }
}

#[derive(Serialize, Deserialize, Hash, PartialEq, Debug, Eq)]
pub enum IndexKind {
    #[serde(rename = "artifact")]
    Artifact,
    #[serde(rename = "zignature")]
    Zignature,
    #[serde(rename = "block")]
    Block,
}

#[derive(Deserialize)]
struct SearchRequest {
    index: IndexKind,
    category: String,
    query: String,
}

#[derive(Serialize, Default)]
struct InfoResult {
    index: HashMap<IndexKind, IndexInfo>,
}

#[derive(Serialize)]
struct IndexInfo {
    fields: Vec<&'static str>,
    categories: HashMap<String, u64>,
}

async fn info_handler(_: Request<Context>) -> tide::Result<Value> {
    let info = FACET_INFO.get().unwrap().lock().await;
    let artifact_facets = info.get(&IndexKind::Artifact).unwrap().clone();
    let zignature_facets = info.get(&IndexKind::Block).unwrap().clone();
    let block_facets = info.get(&IndexKind::Block).unwrap().clone();
    let mut result = InfoResult::default();

    let _ = result.index.insert(
        IndexKind::Artifact,
        IndexInfo {
            fields: vec![
                "category", "name", "sha256", "strings", "links", "imports", "yara",
            ],
            categories: artifact_facets,
        },
    );

    let _ = result.index.insert(
        IndexKind::Zignature,
        IndexInfo {
            fields: vec![
                "category",
                "name",
                "artifact_sha256",
                "artifact_name",
                "masked",
                "ssdeep",
                "entropy",
                "size",
                "bbsum",
                "vars",
            ],
            categories: zignature_facets,
        },
    );

    let _ = result.index.insert(
        IndexKind::Block,
        IndexInfo {
            fields: vec![
                "category",
                "name",
                "artifact_sha256",
                "artifact_name",
                "ssdeep",
                "entropy",
                "size",
            ],
            categories: block_facets,
        },
    );

    Ok(json!(result))
}

async fn search_handler(mut req: Request<Context>) -> tide::Result<Value> {
    let search_request: SearchRequest = req.body_json().await?;
    let mut limit = 100;
    if let Some((name, value)) = req.url().query_pairs().next() {
        if name == "limit" {
            limit = value.parse::<usize>()?
        }
    }

    let result: tide::Result<Vec<NamedFieldDocument>> = spawn_blocking(move || {
        let (searcher, index) = match search_request.index {
            IndexKind::Artifact => {
                let index = &req.state().artifact_index;
                let searcher = req.state().artifact_index_reader.searcher();
                (searcher, index)
            }
            IndexKind::Zignature => {
                let index = &req.state().zignature_index;
                let searcher = req.state().zignature_index_reader.searcher();
                (searcher, index)
            }
            IndexKind::Block => {
                let index = &req.state().block_index;
                let searcher = req.state().block_index_reader.searcher();
                (searcher, index)
            }
        };
        let schema = index.schema();
        let query_parser = QueryParser::for_index(index, vec![schema.get_field("name").unwrap()]);
        let query_string = format!(
            "{} +category:{}",
            search_request.query, search_request.category
        );
        let query = query_parser
            .parse_query(&query_string)
            .map_err(|err| tide::Error::from_str(422, err.to_string()))?;
        let docs = core::query_search(searcher, &query, limit)
            .iter()
            .map(|doc| schema.to_named_doc(doc))
            .collect();
        Ok(docs)
    })
    .await;

    Ok(json!(result?))
}

pub async fn start(opt: Opt) -> tide::Result<()> {
    tide::log::start();

    let context = Context::new(opt.index_dir);

    tide::log::info!("building facet information...");
    FACET_INFO
        .set(Mutex::new(core::all_facet_counts(&context)))
        .unwrap();

    let mut app = tide::with_state(context);

    app.at("/info").get(info_handler);
    app.at("/search").post(search_handler);

    app.listen(opt.bind).await?;
    Ok(())
}
