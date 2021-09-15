use crate::Opt;
use async_std::sync::Arc;
use oz_indexer::{index::open_index, schema::*};
use std::path::PathBuf;
use tantivy::Index;

#[derive(Clone)]
pub struct Context {
    pub artifact_index: Arc<Index>,
    pub zignature_index: Arc<Index>,
    pub block_index: Arc<Index>,
}

impl Context {
    fn new(index_dir: PathBuf) -> Self {
        let index_dir = Some(index_dir);
        let schemas = Schemas::default();
        Context {
            artifact_index: Arc::new(
                open_index(index_dir.clone(), SchemaKind::Artifact(schemas.artifact)).unwrap(),
            ),
            zignature_index: Arc::new(
                open_index(index_dir.clone(), SchemaKind::Zignature(schemas.zignature)).unwrap(),
            ),
            block_index: Arc::new(open_index(index_dir, SchemaKind::Block(schemas.block)).unwrap()),
        }
    }
}

pub async fn start(opt: Opt) -> tide::Result<()> {
    tide::log::start();

    let mut app = tide::with_state(Context::new(opt.index_dir));

    Ok(())
}
