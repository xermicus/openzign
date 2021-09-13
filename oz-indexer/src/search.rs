use crate::{index, schema::SchemaKind};
use std::path::PathBuf;
use tantivy::{collector::FacetCollector, query::AllQuery, schema::Facet};

pub fn cmd_util(index_dir: PathBuf, schema_kind: SchemaKind, category: String, _term: String) {
    let index = index::open_index(Some(index_dir), schema_kind).unwrap();
    let reader = index.reader().unwrap();
    let searcher = reader.searcher();

    let category_field = index.schema().get_field("category").unwrap();
    let mut fc = FacetCollector::for_field(category_field);
    fc.add_facet(&category);

    let facet_counts = searcher.search(&AllQuery, &fc).unwrap();
    let facets: Vec<(&Facet, u64)> = facet_counts.get(&category).collect();
    for (facet, count) in facets {
        println!("{} {}", facet, count)
    }
}
