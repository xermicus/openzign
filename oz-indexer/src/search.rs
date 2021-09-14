use crate::{index, schema::SchemaKind};
use std::path::PathBuf;
use tantivy::{
    collector::{DocSetCollector, FacetCollector},
    query::{AllQuery, QueryParser},
    schema::Facet,
    Index, LeasedItem, Searcher,
};

fn facet_count(searcher: LeasedItem<Searcher>, index: &Index, category: String) {
    let category_field = index.schema().get_field("category").unwrap();
    let mut fc = FacetCollector::for_field(category_field);
    fc.add_facet(&category);

    let facet_counts = searcher.search(&AllQuery, &fc).unwrap();
    let facets: Vec<(&Facet, u64)> = facet_counts.get(&category).collect();
    for (facet, count) in facets {
        println!("{} {}", facet, count)
    }
}

fn query_search(searcher: LeasedItem<Searcher>, index: &Index, term: String) {
    let query_parser =
        QueryParser::for_index(&index, vec![index.schema().get_field("name").unwrap()]);
    let query = query_parser.parse_query(&term).unwrap();
    let docs = searcher.search(&query, &DocSetCollector {}).unwrap();
    println!("found {} documents", docs.len());
    for doc in docs {
        let retrieved = searcher.doc(doc).unwrap();
        println!("{}", index.schema().to_json(&retrieved));
    }
}

pub fn cmd_util(
    index_dir: PathBuf,
    schema_kind: SchemaKind,
    category: Option<String>,
    term: Option<String>,
) {
    let index = index::open_index(Some(index_dir), schema_kind).unwrap();
    let reader = index.reader().unwrap();
    let searcher = reader.searcher();

    if let Some(term) = term {
        return query_search(searcher, &index, term);
    }
    if let Some(category) = category {
        return facet_count(searcher, &index, category);
    }

    println!("wrong usage, check --help")
}
