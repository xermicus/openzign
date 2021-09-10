use std::path::PathBuf;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::*;
use tantivy::tokenizer::NgramTokenizer;
use tantivy::{doc, Index};

fn create_artifacts_schema(index_dir: PathBuf) -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.build()
}

fn create_zignatures_schema(index_dir: PathBuf) -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.build()
}

fn create_segments_schema(index_dir: PathBuf) -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.build()
}
