use oz_datamodel::FileInfo;
use std::{
    fs,
    path::PathBuf,
    str::FromStr,
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::Instant,
};
use tantivy::{
    directory::MmapDirectory,
    schema::*,
    tokenizer::{NgramTokenizer, SimpleTokenizer},
    Index, IndexWriter, TantivyError,
};

use crate::schema::{SchemaKind, Schemas};

/// Get the index for a Schema:
/// If the `dir` arg is `None`, a new index in RAM will be created.
/// If there is already an index inside `dir`/`name` then this index will be used.
/// Otherwise a new index will be created inside `dir`/`name`.
pub fn open_index(dir: Option<PathBuf>, schema_kind: SchemaKind) -> Result<Index, TantivyError> {
    let name = schema_kind.to_string();
    let s = match schema_kind {
        SchemaKind::Artifact(s) => s,
        SchemaKind::Zignature(s) => s,
        SchemaKind::Block(s) => s,
    };
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
        .register("ngram3", NgramTokenizer::new(4, 6, false));
    index.tokenizers().register("simple", SimpleTokenizer {});
    Ok(index)
}

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

fn spawn_indexer(
    in_queue: Receiver<Document>,
    mut index: IndexWriter,
    commit_after: usize,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut count: usize = 0;
        while let Ok(doc) = in_queue.recv() {
            index.add_document(doc);
            count += 1;
            if count % commit_after == 0 {
                index.commit().unwrap();
            }
        }
        index.commit().unwrap();
    })
}

pub fn cmd_util(
    input_dir: PathBuf,
    index_dir: Option<PathBuf>,
    n_workers: usize,
    tantivy_threads: usize,
    heap_size: usize,
    commit_after: usize,
    category: String,
) {
    let schemas = Schemas::default();

    let artifact_index =
        open_index(index_dir.clone(), SchemaKind::from_str("artifact").unwrap()).unwrap();
    let artifact_index_writer = artifact_index
        .writer_with_num_threads(tantivy_threads, heap_size)
        .unwrap();

    let block_index =
        open_index(index_dir.clone(), SchemaKind::from_str("block").unwrap()).unwrap();
    let block_index_writer = block_index
        .writer_with_num_threads(tantivy_threads, heap_size)
        .unwrap();

    let zignature_index =
        open_index(index_dir, SchemaKind::from_str("zignature").unwrap()).unwrap();
    let zignature_index_writer = zignature_index
        .writer_with_num_threads(tantivy_threads, heap_size)
        .unwrap();

    let mut indexers = Vec::with_capacity(n_workers);
    let (artifact_tx, artifact_rx) = channel();
    let (zignature_tx, zignature_rx) = channel();
    let (block_tx, block_rx) = channel();
    indexers.push(spawn_indexer(
        artifact_rx,
        artifact_index_writer,
        commit_after,
    ));
    indexers.push(spawn_indexer(
        zignature_rx,
        zignature_index_writer,
        commit_after,
    ));
    indexers.push(spawn_indexer(block_rx, block_index_writer, commit_after));

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
                category.clone(),
            ),
        ));
    }

    let input_dir = input_dir;
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
        "done indexing {} samples in {}s ({:.2} sample/s)",
        count,
        stop,
        count as f64 / stop as f64
    )
}
