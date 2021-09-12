use oz_datamodel::*;
use schema::Schemas;
use std::{
    path::PathBuf,
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::Instant,
};
use tantivy::{Document, IndexWriter};

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "oz-indexer")]
struct Opt {
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
}

pub mod index;
pub mod schema;

fn spawn_parser(
    in_queue: Receiver<PathBuf>,
    artifact_tx: Sender<Document>,
    zignature_tx: Sender<Document>,
    block_tx: Sender<Document>,
    schemas: Schemas,
    origin: String,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while let Ok(file) = in_queue.recv() {
            let reader = std::fs::File::open(file).unwrap();
            let info: FileInfo = serde_json::from_reader(reader).unwrap();
            artifact_tx
                .send(info.get_artifact(&schemas.artifact, &origin))
                .unwrap();
            for doc in info.get_blocks(&schemas.block, &origin) {
                block_tx.send(doc).unwrap()
            }
            for doc in info.get_zignatures(&schemas.zignature, &origin) {
                zignature_tx.send(doc).unwrap()
            }
        }
    })
}

fn spawn_indexer(in_queue: Receiver<Document>, mut index: IndexWriter) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut count: usize = 0;
        while let Ok(doc) = in_queue.recv() {
            index.add_document(doc);
            count += 1;
            if count % 1000 == 0 {
                index.commit().unwrap();
            }
        }
        index.commit().unwrap();
    })
}

fn main() {
    let opt = Opt::from_args();
    let n_workers = opt.workers.unwrap_or_else(|| num_cpus::get());

    let schemas = Schemas::default();

    let artifact_index =
        index::create_index(opt.index_dir.clone(), schemas.artifact.clone(), "artifacts").unwrap();
    let artifact_index_writer = artifact_index.writer(opt.heap_size).unwrap();

    let block_index =
        index::create_index(opt.index_dir.clone(), schemas.block.clone(), "blocks").unwrap();
    let block_index_writer = block_index.writer(opt.heap_size).unwrap();

    let zignature_index = index::create_index(
        opt.index_dir.clone(),
        schemas.zignature.clone(),
        "zignatures",
    )
    .unwrap();
    let zignature_index_writer = zignature_index.writer(opt.heap_size).unwrap();

    let mut indexers = Vec::with_capacity(n_workers);
    let (artifact_tx, artifact_rx) = channel();
    let (zignature_tx, zignature_rx) = channel();
    let (block_tx, block_rx) = channel();
    indexers.push(spawn_indexer(artifact_rx, artifact_index_writer));
    indexers.push(spawn_indexer(zignature_rx, zignature_index_writer));
    indexers.push(spawn_indexer(block_rx, block_index_writer));

    let mut parsers = Vec::with_capacity(n_workers);
    for _ in 0..n_workers {
        let (tx, rx) = channel();
        parsers.push((
            tx,
            spawn_parser(
                rx,
                artifact_tx.clone(),
                zignature_tx.clone(),
                block_tx.clone(),
                schemas.clone(),
                opt.category.clone(),
            ),
        ));
    }

    let input_dir = opt.input_dir.clone();
    let start = Instant::now();
    let mut worker = 0;
    let mut count = 0;
    for entry in input_dir
        .read_dir()
        .expect("failed to read input dir")
        .flatten()
    {
        // simple roundrobin should work OK here
        if worker < parsers.len() - 1 {
            worker += 1;
        } else {
            worker = 0;
        }
        parsers.get(worker).unwrap().0.send(entry.path()).unwrap();
        count += 1;
    }

    // drop all senders when we are done
    drop(artifact_tx);
    drop(zignature_tx);
    drop(block_tx);
    for parser in parsers {
        drop(parser.0);
        parser.1.join().unwrap();
    }
    println!("waiting for indexers to finish...");
    for indexer in indexers {
        indexer.join().unwrap()
    }

    let stop = start.elapsed().as_secs();
    println!(
        "done indexing {} documents in {}s ({:.2} document/s)",
        count,
        stop,
        count as f64 / stop as f64
    )
}
