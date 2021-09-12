use std::path::PathBuf;
use tantivy::directory::MmapDirectory;
use tantivy::schema::*;
use tantivy::tokenizer::SimpleTokenizer;
use tantivy::Index;
use tantivy::TantivyError;

pub(crate) fn create_index(
    dir: Option<PathBuf>,
    s: Schema,
    name: &'static str,
) -> Result<Index, TantivyError> {
    let index = match dir {
        Some(mut d) => {
            d.push(name);
            match std::fs::create_dir(d.clone()) {
                _ => {}
            }
            Index::open_or_create(MmapDirectory::open(d)?, s)
        }
        _ => Ok(Index::create_in_ram(s)),
    }?;
    index
        .tokenizers()
        //.register("maskedbytes", NgramTokenizer::new(3, 3, false));
        .register("maskedbytes", SimpleTokenizer {});
    Ok(index)
}
