use tantivy::schema::*;

#[derive(Clone)]
pub struct Schemas {
    pub artifact: Schema,
    pub block: Schema,
    pub zignature: Schema,
}

impl Default for Schemas {
    fn default() -> Self {
        Schemas {
            artifact: create_artifacts_schema(),
            block: create_blocks_schema(),
            zignature: create_zignatures_schema(),
        }
    }
}

fn create_artifacts_schema() -> Schema {
    let mut schema_builder = Schema::builder();

    schema_builder.add_facet_field("category", INDEXED);

    schema_builder.add_text_field("sha256", STRING | STORED);

    let name_text_options = TextOptions::default()
        .set_indexing_options(
            TextFieldIndexing::default().set_index_option(IndexRecordOption::WithFreqsAndPositions),
        )
        .set_stored();
    schema_builder.add_text_field("name", name_text_options);

    schema_builder.add_u64_field("size", INDEXED);
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

fn create_zignatures_schema() -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.add_facet_field("category", INDEXED);
    schema_builder.add_text_field("artifact", STRING | STORED);
    schema_builder.add_text_field("name", TEXT);
    schema_builder.add_text_field("ssdeep", TEXT | STORED);
    schema_builder.add_f64_field("entropy", INDEXED | STORED);
    schema_builder.add_u64_field("size", INDEXED | STORED);
    schema_builder.add_u64_field("bbsum", INDEXED | STORED);
    schema_builder.add_u64_field("vars", INDEXED | STORED);
    //schema_builder.add_f64_field("bytes", STORED);
    //schema_builder.add_f64_field("mask", STORED);

    let masked_text_options = TextOptions::default()
        .set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer("maskedbytes")
                .set_index_option(IndexRecordOption::WithFreqsAndPositions),
        )
        .set_stored();
    schema_builder.add_text_field("masked", masked_text_options);

    schema_builder.build()
}

fn create_blocks_schema() -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.add_facet_field("category", INDEXED);
    schema_builder.add_text_field("artifact", STRING | STORED);
    schema_builder.add_text_field("name", TEXT);
    schema_builder.add_text_field("ssdeep", TEXT | STORED);
    schema_builder.add_f64_field("entropy", INDEXED);
    schema_builder.add_u64_field("size", INDEXED);
    schema_builder.build()
}
