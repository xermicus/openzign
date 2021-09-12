use std::{fs, path::PathBuf};
use tantivy::directory::MmapDirectory;
use tantivy::schema::*;
use tantivy::tokenizer::SimpleTokenizer;
use tantivy::Index;
use tantivy::TantivyError;

/// Get the index for a Schema:
/// If the `dir` arg is `None`, a new index in RAM will be created.
/// If there is already an index inside `dir`/`name` then this index will be used.
/// Otherwise a new index will be created inside `dir`/`name`.
pub fn open_index(
    dir: Option<PathBuf>,
    s: Schema,
    name: &'static str,
) -> Result<Index, TantivyError> {
    let index = match dir {
        Some(mut d) => {
            d.push(name);
            if d.is_dir() {
                println!("opening existing index in {}", d.display())
            } else {
                fs::create_dir(d.clone())
                    .unwrap_or_else(|_| panic!("failed to create index directory {}", d.display()))
            }
            Index::open_or_create(MmapDirectory::open(d)?, s)
        }
        _ => Ok(Index::create_in_ram(s)),
    }?;
    index
        .tokenizers()
        //.register("ngram3", NgramTokenizer::new(3, 3, false));
        .register("simple", SimpleTokenizer {});
    Ok(index)
}
