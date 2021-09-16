use oz_indexer::{index, schema::SchemaKind, search};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "oz-indexer")]
pub enum Opt {
    #[structopt(name = "search")]
    Search {
        #[structopt(
            short,
            long,
            help = "'artifact' (generall Information), 'zignature' (radare2 Zignatures information) or 'block' (Segments and Sections)"
        )]
        schema: SchemaKind,

        #[structopt(
            short,
            long,
            default_value = "/",
            help = "Search facet (category) for fuzzy search or facet counts"
        )]
        category: String,

        #[structopt(
            short,
            long,
            help = "Use '<fieldname>:<searchterm>' to search for a specific field only. Sytnax: https://docs.rs/tantivy/latest/tantivy/query/struct.QueryParser.html"
        )]
        query: Option<String>,

        #[structopt(
            short = "x",
            long,
            parse(from_os_str),
            help = "Directory in which the search index is stored"
        )]
        index_dir: PathBuf,

        #[structopt(
            short = "f",
            long,
            help = "If set, a fuzzy search for this field name is performed (provide the search term in the query argument)"
        )]
        fuzzy: Option<String>,

        #[structopt(
            short = "d",
            long,
            default_value = "2",
            help = "Levenshtein distance for fuzzy searches"
        )]
        fuzzy_distance: u8,
    },

    #[structopt(name = "index")]
    Index {
        #[structopt(
            short,
            long,
            parse(from_os_str),
            help = "The directory from which to read the FileInfo JSON files"
        )]
        input_dir: PathBuf,

        #[structopt(
            short = "x",
            long,
            parse(from_os_str),
            help = "If omitted, the index will be stored RAM"
        )]
        index_dir: Option<PathBuf>,

        #[structopt(
            short,
            long,
            help = "Amount of worker threads to use for reading and parsing FileInfo JSON files"
        )]
        workers: Option<usize>,

        #[structopt(
        short,
        long,
        default_value = "200000000", // 200mb
        help = "Heap size of tantivy indexer threads"
    )]
        heap_size: usize,

        #[structopt(
            short,
            long,
            help = "Top level facet (category field) of the document collection getting indexed"
        )]
        category: String,
    },
}

fn main() {
    match Opt::from_args() {
        Opt::Search {
            index_dir,
            schema,
            category,
            query,
            fuzzy,
            fuzzy_distance,
        } => search::cmd_util(index_dir, schema, category, query, fuzzy, fuzzy_distance),

        Opt::Index {
            index_dir,
            input_dir,
            workers,
            heap_size,
            category,
        } => {
            let n_workers = workers.unwrap_or_else(num_cpus::get);
            index::cmd_util(input_dir, index_dir, n_workers, heap_size, category)
        }
    }
}
