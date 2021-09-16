use crate::{index, schema::SchemaKind};
use std::path::PathBuf;
use tantivy::{
    collector::{DocSetCollector, FacetCollector, TopDocs},
    query::{AllQuery, BooleanQuery, FuzzyTermQuery, Occur, Query, QueryParser, TermQuery},
    schema::{Facet, Term},
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

fn fuzzy_search(
    searcher: LeasedItem<Searcher>,
    index: &Index,
    category: &str,
    query: &str,
    field: &str,
    distance: u8,
) {
    let fuzzy_term = Term::from_field_text(index.schema().get_field(field).unwrap(), query);
    let fuzzy_query = FuzzyTermQuery::new(fuzzy_term, distance, false);

    let facet_term = Term::from_facet(
        index.schema().get_field("category").unwrap(),
        &Facet::from(category),
    );
    let facet_query = TermQuery::new(facet_term, tantivy::schema::IndexRecordOption::Basic);

    let term_and_facet_query: Vec<(Occur, Box<dyn Query>)> = vec![
        (Occur::Must, Box::new(fuzzy_query)),
        (Occur::Must, Box::new(facet_query)),
    ];
    let query = BooleanQuery::new(term_and_facet_query);

    let docs = searcher.search(&query, &DocSetCollector {}).unwrap();
    println!("found {} documents", docs.len());
    for doc in docs {
        let retrieved = searcher.doc(doc).unwrap();
        println!("{}", index.schema().to_json(&retrieved));
    }
}

fn query_search(searcher: LeasedItem<Searcher>, index: &Index, term: &str) {
    let query_parser =
        QueryParser::for_index(index, vec![index.schema().get_field("name").unwrap()]);
    let query = query_parser.parse_query(term).unwrap();
    let docs = searcher.search(&query, &TopDocs::with_limit(100)).unwrap();
    println!("found {} documents", docs.len());
    for doc in docs {
        let retrieved = searcher.doc(doc.1).unwrap();
        println!("{}", index.schema().to_json(&retrieved));
    }
}

pub fn cmd_util(
    index_dir: PathBuf,
    schema_kind: SchemaKind,
    category: String,
    term: Option<String>,
    fuzzy: Option<String>,
    fuzzy_distance: u8,
) {
    let index = index::open_index(Some(index_dir), schema_kind).unwrap();
    let reader = index.reader().unwrap();
    let searcher = reader.searcher();

    if let Some(term) = term {
        if let Some(field) = fuzzy {
            fuzzy_search(searcher, &index, &category, &term, &field, fuzzy_distance)
        } else {
            query_search(
                searcher,
                &index,
                &format!("{} +category:{}", term, category),
            )
        }
    } else {
        facet_count(searcher, &index, category)
    }
}
