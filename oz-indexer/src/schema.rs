use std::path::PathBuf;
use std::string;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::*;
use tantivy::{doc, Index};

fn create_artifacts_schema(index_dir: PathBuf) -> Schema {
    let mut schema_builder = Schema::builder();

    schema_builder.add_facet_field("category", INDEXED);

    //let sha256_text_options = TextOptions::default()
    //    .set_indexing_options(
    //        TextFieldIndexing::default()
    //            .set_tokenizer("raw")
    //            .set_index_option(IndexRecordOption::Basic),
    //    )
    //    .set_stored();
    //schema_builder.add_text_field("sha256", sha256_text_options);
    schema_builder.add_text_field("sha256", STRING | STORED);

    let name_text_options = TextOptions::default()
        .set_indexing_options(
            TextFieldIndexing::default().set_index_option(IndexRecordOption::WithFreqs),
        )
        .set_stored();
    schema_builder.add_text_field("name", name_text_options);

    schema_builder.add_f64_field("size", INDEXED);
    schema_builder.add_text_field("magic", TEXT);
    schema_builder.add_text_field("error", TEXT);

    let strings_text_options = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default().set_index_option(IndexRecordOption::WithFreqs),
    );
    schema_builder.add_text_field("strings", strings_text_options.clone());
    schema_builder.add_text_field("links", strings_text_options.clone());
    schema_builder.add_text_field("imports", strings_text_options.clone());
    schema_builder.add_text_field("yara", strings_text_options);

    schema_builder.build()
}

fn create_zignatures_schema(index_dir: PathBuf) -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.add_facet_field("category", INDEXED);
    schema_builder.add_text_field("name", TEXT);
    schema_builder.add_text_field("ssdeep", TEXT | STORED);
    schema_builder.add_f64_field("entropy", INDEXED | STORED);
    schema_builder.add_f64_field("size", INDEXED | STORED);
    schema_builder.add_f64_field("bbsum", INDEXED | STORED);
    schema_builder.add_f64_field("vars", INDEXED | STORED);
    schema_builder.add_f64_field("bytes", STORED);
    schema_builder.add_f64_field("mask", STORED);

    let masked_text_options = TextOptions::default()
        .set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer("maskedbytes")
                .set_index_option(IndexRecordOption::WithFreqs),
        )
        .set_stored();
    schema_builder.add_text_field("masked", masked_text_options);

    schema_builder.build()
}

fn create_segments_schema(index_dir: PathBuf) -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.add_facet_field("category", INDEXED);
    schema_builder.add_text_field("name", TEXT);
    schema_builder.add_text_field("ssdeep", TEXT | STORED);
    schema_builder.add_f64_field("entropy", INDEXED);
    schema_builder.add_f64_field("size", INDEXED);
    schema_builder.build()
}
