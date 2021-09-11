use clap::{App, Arg, SubCommand};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{channel, Receiver, Sender},
    thread,
};

mod index;
mod schema;

fn spawn_worker(
    id: usize,
    in_queue: Receiver<String>,
    notify: Sender<usize>,
    out_dir: PathBuf,
) -> thread::JoinHandle<()> {
    todo!()
}

fn main() {
    let matches = App::new("openZign indexer")
        .version("0.1")
        .about("Index binary analysis files")
        .arg(Arg::with_name("input-dir").required(true))
        .arg(Arg::with_name("index-dir").required(false))
        .get_matches();

    let workdir = Path::new(matches.value_of("input-dir").unwrap());
    if !workdir.is_dir() {
        panic!("invalid input-dir ({})", &workdir.display(),)
    }

    let indexdir = matches.value_of("index_dir").map(|arg| {
        let p = Path::new(arg);
        if !p.is_dir() {
            panic!("invalid index-dir ({})", &workdir.display(),)
        }
        p.to_path_buf()
    });

    let a_schema = schema::create_artifacts_schema();
    let a_index = index::create_artifacts_index(indexdir, a_schema).unwrap();
    let a_index_writer = a_index.writer(100_000_000).unwrap();
    for entry in workdir
        .read_dir()
        .expect("failed to read input dir")
        .flatten()
    {
        let file = entry.path().display().to_string();
        println!("processing {}", &file);
        //let info: oz_fila::FileInfo = oz_fila::FileInfo::default();
    }
}
