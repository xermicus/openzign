use serde::Serialize;
use std::{collections::HashMap, thread, time::Instant};
use tantivy::{
    collector::{FacetCollector, TopDocs},
    query::{AllQuery, Query},
    schema::{NamedFieldDocument, Schema},
    LeasedItem, Searcher,
};

#[derive(Serialize)]
pub struct Match {
    pub document: NamedFieldDocument,
    pub score: f32,
}

use crate::server::{Context, IndexKind};

fn facet_count(
    searcher: &LeasedItem<Searcher>,
    schema: Schema,
    category: String,
) -> Vec<(String, u64)> {
    let category_field = schema.get_field("category").unwrap();
    let mut fc = FacetCollector::for_field(category_field);
    fc.add_facet(&category);

    let facet_counts = searcher.search(&AllQuery, &fc).unwrap();
    facet_counts
        .get(&category)
        .map(|(facet, count)| (facet.to_string(), count))
        .collect()
}

fn recursive_facet_count<'a>(
    searcher: &'a LeasedItem<Searcher>,
    index: &IndexKind,
    schema: Schema,
    category: String,
    result: &'a mut HashMap<String, u64>,
) -> &'a mut HashMap<String, u64> {
    for (facet, count) in facet_count(searcher, schema.clone(), category) {
        tide::log::info!("facet count {:?} {} {}", index, &facet, count);
        let _ = result.insert(facet.clone(), count);
        if facet.split('/').count() < 4 {
            recursive_facet_count(searcher, index, schema.clone(), facet, result);
        }
    }
    result
}

pub fn all_facet_counts(context: &Context) -> HashMap<IndexKind, HashMap<String, u64>> {
    let mut result = HashMap::new();
    let start = Instant::now();

    let artifact_searcher = context.artifact_index_reader.searcher();
    let artifact_schema = context.artifact_index.schema();
    let artifact_facets = thread::spawn(move || {
        let mut artifact_facets = HashMap::new();
        recursive_facet_count(
            &artifact_searcher,
            &IndexKind::Artifact,
            artifact_schema,
            "/".to_string(),
            &mut artifact_facets,
        );
        artifact_facets
    });

    let zignature_searcher = context.zignature_index_reader.searcher();
    let zignature_schema = context.zignature_index.schema();
    let zignature_facets = thread::spawn(move || {
        let mut zignature_facets = HashMap::new();
        recursive_facet_count(
            &zignature_searcher,
            &IndexKind::Zignature,
            zignature_schema,
            "/".to_string(),
            &mut zignature_facets,
        );
        zignature_facets
    });

    let mut block_facets = HashMap::new();
    recursive_facet_count(
        &context.block_index_reader.searcher(),
        &IndexKind::Block,
        context.block_index.schema(),
        "/".to_string(),
        &mut block_facets,
    );

    result.insert(IndexKind::Artifact, artifact_facets.join().unwrap());
    result.insert(IndexKind::Zignature, zignature_facets.join().unwrap());
    result.insert(IndexKind::Block, block_facets);

    let stop = start.elapsed().as_secs();
    tide::log::info!("facet counting took {}s", stop);
    result
}

pub fn query_search(
    searcher: LeasedItem<Searcher>,
    query: &dyn Query,
    schema: &Schema,
    limit: usize,
) -> Vec<Match> {
    let docs = searcher.search(query, &TopDocs::with_limit(limit)).unwrap();
    docs.iter()
        .map(|(score, doc_addr)| Match {
            score: *score,
            document: schema.to_named_doc(&searcher.doc(*doc_addr).unwrap()),
        })
        .collect()
}
