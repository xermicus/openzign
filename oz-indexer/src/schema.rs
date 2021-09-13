use tantivy::schema::*;

#[derive(Debug)]
pub enum SchemaKind {
    Artifact(Schema),
    Zignature(Schema),
    Block(Schema),
}

impl std::str::FromStr for SchemaKind {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "artifact" => Ok(SchemaKind::Artifact(create_artifacts_schema())),
            "zignature" => Ok(SchemaKind::Zignature(create_zignatures_schema())),
            "block" => Ok(SchemaKind::Block(create_blocks_schema())),
            _ => Err("invalid schema kind"),
        }
    }
}

impl std::string::ToString for SchemaKind {
    fn to_string(&self) -> String {
        match self {
            SchemaKind::Artifact(_) => String::from("artifact"),
            SchemaKind::Zignature(_) => String::from("zignature"),
            SchemaKind::Block(_) => String::from("block"),
        }
    }
}

#[derive(Clone, Debug)]
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

    schema_builder.add_facet_field("category", INDEXED | STORED);

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
    schema_builder.add_text_field("artifact_hash", STRING | STORED);
    schema_builder.add_text_field("artifact_name", STRING | STORED);
    schema_builder.add_text_field("name", TEXT | STORED);
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
                .set_tokenizer("simple")
                .set_index_option(IndexRecordOption::WithFreqsAndPositions),
        )
        .set_stored();
    schema_builder.add_text_field("masked", masked_text_options);

    schema_builder.build()
}

fn create_blocks_schema() -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.add_facet_field("category", INDEXED);
    schema_builder.add_text_field("artifact_hash", STRING | STORED);
    schema_builder.add_text_field("artifact_name", STRING | STORED);
    schema_builder.add_text_field("name", TEXT | STORED);
    schema_builder.add_text_field("ssdeep", TEXT | STORED);
    schema_builder.add_f64_field("entropy", INDEXED | STORED);
    schema_builder.add_u64_field("size", INDEXED | STORED);
    schema_builder.build()
}
