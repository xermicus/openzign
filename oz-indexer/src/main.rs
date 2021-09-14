use oz_indexer::{index, schema, search};
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
        schema: schema::SchemaKind,

        #[structopt(
            short,
            long,
            help = "Search facet (category) for fuzzy search or facet counts"
        )]
        category: Option<String>,

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
        default_value = "100000000", // 100mb
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
        } => search::cmd_util(index_dir, schema, category, query),

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
