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
        .arg(Arg::with_name("input dir").required(true))
        .arg(Arg::with_name("index dir").required(true))
        .get_matches();
    let workdir = Path::new(matches.value_of("input dir").unwrap());
    let indexdir = Path::new(matches.value_of("index dir").unwrap());
    if !workdir.is_dir() || !indexdir.is_dir() {
        panic!(
            "input dir ({}) and index dir ({}) must be directories",
            &workdir.display(),
            &indexdir.display(),
        )
    }
}
