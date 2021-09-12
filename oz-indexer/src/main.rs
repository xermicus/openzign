use oz_datamodel::*;
use schema::Schemas;
use std::{
    path::PathBuf,
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::Instant,
};
use tantivy::Document;

enum DocType {
    Artifact(Document),
    Zignature(Document),
    Block(Document),
}

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
        default_value = "4",
        help = "Amount of worker threads to use for reading and parsing FileInfo JSON files"
    )]
    workers: u8,

    #[structopt(
        short,
        long,
        default_value = "50000000", // 50mb
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

mod index;
mod schema;

fn spawn_worker(
    in_queue: Receiver<PathBuf>,
    notify: Sender<DocType>,
    schemas: Schemas,
    origin: String,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while let Ok(file) = in_queue.recv() {
            let reader = std::fs::File::open(file).unwrap();
            let info: FileInfo = serde_json::from_reader(reader).unwrap();
            notify
                .send(DocType::Artifact(
                    info.get_artifact(&schemas.artifact, &origin),
                ))
                .unwrap();
            for doc in info.get_blocks(&schemas.block, &origin) {
                notify.send(DocType::Block(doc)).unwrap()
            }
            for doc in info.get_zignatures(&schemas.zignature, &origin) {
                notify.send(DocType::Zignature(doc)).unwrap()
            }
        }
    })
}

fn main() {
    let opt = Opt::from_args();

    let schemas = Schemas::default();

    let artifact_index =
        index::create_index(opt.index_dir.clone(), schemas.artifact.clone(), "artifacts").unwrap();
    let mut artifact_index_writer = artifact_index.writer(opt.heap_size).unwrap();

    let block_index =
        index::create_index(opt.index_dir.clone(), schemas.block.clone(), "blocks").unwrap();
    let mut block_index_writer = block_index.writer(opt.heap_size).unwrap();

    let zignature_index = index::create_index(
        opt.index_dir.clone(),
        schemas.zignature.clone(),
        "zignatures",
    )
    .unwrap();
    let mut zignature_index_writer = zignature_index.writer(opt.heap_size).unwrap();

    let mut workers = Vec::with_capacity(opt.workers as usize);
    let (nf_tx, nf_rx) = channel();
    for _ in 0..opt.workers {
        let (tx, rx) = channel();
        workers.push((
            tx,
            spawn_worker(rx, nf_tx.clone(), schemas.clone(), opt.category.clone()),
        ));
    }

    let input_dir = opt.input_dir.clone();
    let start = Instant::now();
    thread::spawn(move || {
        let mut worker = 0;
        for entry in input_dir
            .read_dir()
            .expect("failed to read input dir")
            .flatten()
        {
            // simple roundrobin should work OK here
            if worker < workers.len() - 1 {
                worker += 1;
            } else {
                worker = 0;
            }
            workers.get(worker).unwrap().0.send(entry.path()).unwrap();
        }
        // drop file transmitter when we are done
        drop(nf_tx);
    });

    let mut count: usize = 0;
    while let Ok(doc) = nf_rx.recv() {
        match doc {
            DocType::Artifact(d) => artifact_index_writer.add_document(d),
            DocType::Zignature(d) => zignature_index_writer.add_document(d),
            DocType::Block(d) => block_index_writer.add_document(d),
        };
        count += 1;
        if count % (100 * opt.workers as usize) == 0 {
            artifact_index_writer.commit().unwrap();
            block_index_writer.commit().unwrap();
            zignature_index_writer.commit().unwrap();
        }
    }
    artifact_index_writer.commit().unwrap();
    block_index_writer.commit().unwrap();
    zignature_index_writer.commit().unwrap();

    let stop = start.elapsed().as_secs();
    println!(
        "done indexing {} samples in {}s ({:.2} samples/s)",
        count,
        stop,
        count as f64 / stop as f64
    )
}
