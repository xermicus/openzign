use std::path::PathBuf;
use tantivy::directory::MmapDirectory;
use tantivy::schema::*;
use tantivy::Index;
use tantivy::TantivyError;

pub(crate) fn create_artifacts_index(
    dir: Option<PathBuf>,
    s: Schema,
) -> Result<Index, TantivyError> {
    match dir {
        Some(mut d) => {
            d.push("artifacts");
            Index::open_or_create(MmapDirectory::open(d)?, s)
        }
        _ => Ok(Index::create_in_ram(s)),
    }
}
