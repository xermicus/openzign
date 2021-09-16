use std::collections::HashMap;

//use async_std::task::spawn_blocking;
//use oz_indexer::schema::Schemas;
//use std::path::PathBuf;
use tantivy::{
    collector::{FacetCollector, TopDocs},
    query::{AllQuery, Query},
    schema::Schema,
    Document, LeasedItem, Searcher,
};

use crate::server::Context;

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
    index: &str,
    schema: Schema,
    category: String,
    result: &'a mut HashMap<String, u64>,
) -> &'a mut HashMap<String, u64> {
    for (facet, count) in facet_count(searcher, schema.clone(), category) {
        tide::log::info!("facet count {} {} {}", index, &facet, count);
        let _ = result.insert(facet.clone(), count);
        if facet.split('/').count() < 4 {
            recursive_facet_count(searcher, index, schema.clone(), facet, result);
        }
    }
    result
}

pub fn all_facet_counts(context: &Context) -> HashMap<String, HashMap<String, u64>> {
    let mut result = HashMap::new();

    let mut artifact_facets = HashMap::new();
    recursive_facet_count(
        &context.artifact_index_reader.searcher(),
        "artifact",
        context.artifact_index.schema(),
        "/".to_string(),
        &mut artifact_facets,
    );
    result.insert("artifact".to_string(), artifact_facets);

    let mut zignature_facets = HashMap::new();
    recursive_facet_count(
        &context.zignature_index_reader.searcher(),
        "zignature",
        context.zignature_index.schema(),
        "/".to_string(),
        &mut zignature_facets,
    );
    result.insert("zignature".to_string(), zignature_facets);

    let mut block_facets = HashMap::new();
    recursive_facet_count(
        &context.block_index_reader.searcher(),
        "block",
        context.block_index.schema(),
        "/".to_string(),
        &mut block_facets,
    );
    result.insert("block".to_string(), block_facets);

    result
}

pub fn artifact_search(searcher: LeasedItem<Searcher>, query: &dyn Query) -> Vec<Document> {
    let docs = searcher.search(query, &TopDocs::with_limit(2)).unwrap();
    docs.iter()
        .map(|(_, doc_addr)| searcher.doc(*doc_addr).unwrap())
        .collect()
}
