use r2pipe::{R2Pipe, R2PipeSpawnOptions};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, path::PathBuf};

use oz_datamodel::*;

fn spawn_r2(path: &str) -> Result<(R2Pipe, std::process::Child), &'static str> {
    if let Ok(mut r2) = R2Pipe::spawn(
        path,
        Some(R2PipeSpawnOptions {
            exepath: "r2".to_string(),
            args: vec!["-Q", "-S", "-2"],
        }),
    ) {
        let child = if let R2Pipe::Pipe(x) = &mut r2 {
            x.take_child().expect("Cant take r2 child process")
        } else {
            panic!("never happens")
        };
        return Ok((r2, child));
    }
    Err("{\"error\": \"radare2 spawn fail\"}")
}

fn spawn_worker(
    id: usize,
    in_queue: Receiver<String>,
    notify: Sender<usize>,
    out_dir: PathBuf,
) -> thread::JoinHandle<()> {
    let timeout = env::var("WORKER_TIMEOUT")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .unwrap_or(10);
    let yara_rules_file = env::var("YARA_RULES_FILE").expect("please set YARA_RULES_FILE env var");
    if !Path::new(&yara_rules_file).is_file() {
        panic!("YARA_RULES_FILE is not a file")
    }

    thread::spawn(move || {
        if notify.send(id).is_err() {
            return;
        }
        while let Ok(file) = in_queue.recv() {
            let mut info = FileInfo::new(file.clone());
            let mut out_file = out_dir.clone();
            out_file.push(format!("{}.json", &info.name));

            let (tx, rx): (Sender<FileInfo>, Receiver<FileInfo>) = channel();
            let y = yara_rules_file.clone();
            let (mut r2_b, mut ch_b) = match spawn_r2(&info.path) {
                Ok(x) => x,
                _ => {
                    println!("error {} r2 spawn fail", &file);
                    if notify.send(id).is_err() {
                        break;
                    }
                    continue;
                }
            };
            thread::spawn(move || {
                info.anal_basic(&mut r2_b, y);
                let _ = tx.send(info);
                r2_b.close();
            });
            let mut basic = rx.recv_timeout(Duration::from_secs(timeout));

            let (tx_a, rx_a): (Sender<FileInfo>, Receiver<FileInfo>) = channel();
            let mut info = FileInfo::new(file.clone());
            let (mut r2_a, mut ch_a) = match spawn_r2(&info.path) {
                Ok(x) => x,
                _ => {
                    println!("error {} r2 spawn fail", &file);
                    if notify.send(id).is_err() {
                        break;
                    }
                    continue;
                }
            };
            thread::spawn(move || {
                info.anal_advanced(&mut r2_a);
                let _ = tx_a.send(info);
                r2_a.close();
            });
            let advanced = rx_a.recv_timeout(Duration::from_secs(timeout));
            if basic.is_err() {
                // maybe basic info now finished
                basic = rx
                    .try_recv()
                    .map_err(|_| std::sync::mpsc::RecvTimeoutError::Timeout)
            }

            let result = match (basic, advanced) {
                (Ok(mut b), Ok(a)) => {
                    b.zignatures = a.zignatures;
                    thread::spawn(move || {
                        let _ = ch_b.wait();
                        let _ = ch_a.wait();
                    });
                    serde_json::to_string(&b)
                        .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
                }
                (Ok(mut b), Err(_)) => {
                    thread::spawn(move || {
                        let _ = ch_a.kill();
                        let _ = ch_a.wait();
                        let _ = ch_b.wait();
                    });
                    println!("error {} advanced analysis timeout or panic", &file);
                    b.error
                        .push("advanced analysis timeout or panic".to_string());
                    serde_json::to_string(&b)
                        .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
                }
                (Err(_), Ok(mut a)) => {
                    thread::spawn(move || {
                        let _ = ch_b.kill();
                        let _ = ch_b.wait();
                        let _ = ch_a.wait();
                    });
                    println!("error {} basic analysis timeout or panic", &file);
                    a.error.push("basic analysis timeout or panic".to_string());
                    serde_json::to_string(&a)
                        .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
                }
                _ => {
                    thread::spawn(move || {
                        let _ = ch_a.kill();
                        let _ = ch_b.kill();
                        let _ = ch_a.wait();
                        let _ = ch_b.wait();
                    });
                    println!("error {} analysis timeout or panic", &file);
                    "{\"error\": \"timeout or panic during analysis\"}".to_string()
                }
            };
            write_result_file(out_file.as_path(), &result);

            if notify.send(id).is_err() {
                break;
            }
        }
    })
}

fn write_result_file(dest: &Path, content: &str) {
    let err_msg = format!("can not write result file {}", dest.display());
    let mut buffer = File::create(dest).expect(&err_msg);
    buffer.write_all(content.as_bytes()).expect(&err_msg);
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let usage = format!("Usage: {} <input_dir> <output_dir>", args.get(0).unwrap());
    let workdir = Path::new(args.get(1).expect(&usage));
    let outdir = Path::new(args.get(2).expect(&usage));
    if !workdir.is_dir() || !outdir.is_dir() {
        panic!("{}", usage)
    }

    let n_workers = num_cpus::get() + 2;
    let mut workers = Vec::with_capacity(n_workers);
    let (nf_tx, nf_rx) = channel();
    for n in 0..n_workers {
        let (tx, rx) = channel();
        workers.push((tx, spawn_worker(n, rx, nf_tx.clone(), outdir.to_path_buf())))
    }

    let mut count: usize = 0;
    let start = Instant::now();
    for entry in workdir
        .read_dir()
        .expect("failed to read input dir")
        .flatten()
    {
        count += 1;
        let file = entry.path().display().to_string();
        println!("processing {}", &file);
        let w = nf_rx.recv().expect("workers drained out");
        workers
            .get(w)
            .unwrap()
            .0
            .send(file)
            .unwrap_or_else(|_| panic!("worker {} died unexpectedly", w))
    }

    println!("waiting for workers to finish ...");
    drop(nf_rx);
    for worker in workers {
        drop(worker.0);
        let _ = worker.1.join();
    }

    let stop = start.elapsed().as_secs();
    println!(
        "done {} samples in {}s ({:.2} samples/s)",
        count,
        stop,
        count as f64 / stop as f64
    )
}
