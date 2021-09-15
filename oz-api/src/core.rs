//use async_std::task::spawn_blocking;
//use oz_indexer::schema::Schemas;
//use std::path::PathBuf;
use tantivy::{
    collector::{FacetCollector, TopDocs},
    query::{AllQuery, Query},
    schema::Schema,
    Document, LeasedItem, Searcher,
};

pub fn facet_count(
    searcher: LeasedItem<Searcher>,
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

pub fn artifact_search(searcher: LeasedItem<Searcher>, query: &dyn Query) -> Vec<Document> {
    let docs = searcher.search(query, &TopDocs::with_limit(2)).unwrap();
    docs.iter()
        .map(|(_, doc_addr)| searcher.doc((*doc_addr)).unwrap())
        .collect()
}
