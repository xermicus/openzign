use r2pipe::{R2Pipe, R2PipeSpawnOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, path::PathBuf};

#[derive(Deserialize, Serialize, Default)]
pub struct FileInfo {
    #[serde(skip_serializing)]
    pub path: String,
    pub error: Vec<String>,
    pub name: String,
    pub sha256: String,
    pub magic: Vec<String>,
    pub arch: String,
    pub size: u64,
    pub format: String,
    pub bintype: String,
    pub compiler: String,
    pub lang: String,
    pub machine: String,
    pub os: String,
    pub strings: Vec<String>,
    pub imports: Vec<ImportInfo>,
    pub sections: Vec<BlockInfo>,
    pub segments: Vec<BlockInfo>,
    pub links: Vec<String>,
    pub zignatures: Vec<Zignature>,
    pub yara: String,
}

#[derive(Deserialize, Serialize)]
pub struct ImportInfo {
    pub lib: String,
    pub name: String,
}

#[derive(Deserialize, Serialize)]
pub struct BlockInfo {
    pub name: String,
    pub size: u64,
    pub ssdeep: Option<String>,
    pub entropy: Option<f32>,
}

#[derive(Deserialize, Serialize)]
pub struct Zignature {
    pub function: BlockInfo,
    pub bytes: String,
    pub mask: String,
    pub bbsum: u64,
    pub addr: u64,
    pub n_vars: u64,
}

// Dont escape double quotes which happens when using simple `.to_string()`
fn jstr(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

impl FileInfo {
    fn new(path: String) -> Self {
        FileInfo {
            path: path.clone(),
            name: path.split('/').last().unwrap().to_string(),
            ..Default::default()
        }
    }

    fn sha256(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("itj") {
            Ok(json) => {
                self.sha256 = jstr(&json["sha256"]);
            }
            _ => self.error.push("sha256 hash".to_string()),
        }
        self
    }

    fn magic(&mut self, r2: &mut R2Pipe) -> &mut Self {
        let _ = r2.cmd("e search.from = 0");
        let _ = r2.cmd("e search.to = 0x3ff");
        match r2.cmdj("/mj") {
            Ok(Value::Array(magics)) => {
                for magic in magics {
                    self.magic.push(jstr(&magic["info"]))
                }
            }
            _ => self.error.push("magic".to_string()),
        }
        self
    }

    fn info(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("ij") {
            Ok(json) => {
                self.format = jstr(&json["core"]["format"]);
                self.arch = jstr(&json["bin"]["arch"]);
                if let Some(size) = json["bin"]["size"].as_u64() {
                    self.size = size;
                }
                self.bintype = jstr(&json["bin"]["bintype"]);
                self.compiler = jstr(&json["bin"]["compiler"]);
                self.lang = jstr(&json["bin"]["lang"]);
                self.machine = jstr(&json["bin"]["machine"]);
                self.os = jstr(&json["bin"]["os"]);
            }
            _ => self.error.push("info".to_string()),
        }
        self
    }

    fn strings(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("izj") {
            Ok(Value::Array(strings)) => {
                for string in strings {
                    self.strings.push(jstr(&string["string"]))
                }
            }
            _ => self.error.push("strings".to_string()),
        }
        self
    }

    fn imports(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("iij") {
            Ok(Value::Array(imports)) => {
                for import in imports {
                    self.imports.push(ImportInfo {
                        name: jstr(&import["name"]),
                        lib: jstr(&import["lib"]),
                    })
                }
            }
            _ => self.error.push("imports".to_string()),
        }
        self
    }

    fn sections(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("iSj entropy,ssdeep") {
            Ok(json) => {
                if let Value::Array(sections) = &json["sections"] {
                    for section in sections {
                        let name = jstr(&section["name"]);
                        if name.is_empty() {
                            continue;
                        }
                        let size = match section["size"].as_u64() {
                            Some(v) => v,
                            _ => continue,
                        };
                        let entropy = jstr(&section["entropy"]).parse::<f32>().ok();
                        let ssdeep = hex::decode(jstr(&section["ssdeep"]).trim_end_matches("00"))
                            .ok()
                            .and_then(|buf| String::from_utf8(buf).ok());
                        self.sections.push(BlockInfo {
                            name,
                            size,
                            ssdeep,
                            entropy,
                        })
                    }
                }
            }
            _ => self.error.push("sections".to_string()),
        }
        self
    }

    fn segments(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("iSSj entropy,ssdeep") {
            Ok(json) => {
                if let Value::Array(segments) = &json["segments"] {
                    for segment in segments {
                        let name = jstr(&segment["name"]);
                        if name.is_empty() {
                            continue;
                        }
                        let size = match segment["size"].as_u64() {
                            Some(v) => v,
                            _ => continue,
                        };
                        let entropy = jstr(&segment["entropy"]).parse::<f32>().ok();
                        let ssdeep = hex::decode(jstr(&segment["ssdeep"]).trim_end_matches("00"))
                            .ok()
                            .and_then(|buf| String::from_utf8(buf).ok());
                        self.segments.push(BlockInfo {
                            name,
                            size,
                            ssdeep,
                            entropy,
                        })
                    }
                }
            }
            _ => self.error.push("segments".to_string()),
        }
        self
    }

    fn links(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("ilj") {
            Ok(Value::Array(links)) => {
                for link in links {
                    self.links.push(jstr(&link))
                }
            }
            _ => self.error.push("strings".to_string()),
        }
        self
    }

    fn yara(&mut self, yara_rules_file: String) -> &mut Self {
        let err = "yara processing error".to_string();
        self.yara = match Command::new("yara")
            .arg("-f")
            .arg("-w")
            .arg(&yara_rules_file)
            .arg(&self.path)
            .output()
        {
            Ok(result) => String::from_utf8(result.stdout).map_or(err, |rule_matches| {
                rule_matches.replace(&self.path, "").replace("\n", "")
            }),
            _ => err,
        };
        self
    }

    fn zignatures(&mut self, r2: &mut R2Pipe) -> &mut Self {
        let _ = r2.cmd("aa;zaF");
        match r2.cmdj("zj") {
            Ok(Value::Array(zignatures)) => {
                for zign in zignatures {
                    let name = jstr(&zign["name"]);
                    let bytes = jstr(&zign["bytes"]);
                    let size = bytes.len() as u64;
                    let mask = jstr(&zign["mask"]);
                    let bbsum = zign["graph"]["bbsum"].as_u64().unwrap_or(0);
                    let addr = zign["addr"].as_u64().unwrap_or(0);
                    let n_vars = match zign["vars"].as_array() {
                        Some(v) => v.len() as u64,
                        _ => 0,
                    };
                    let ssdeep = r2
                        .cmd(&format!("ph ssdeep {} @ {}", size, name))
                        .ok()
                        .map(|v| v.trim().to_string());
                    let entropy = r2
                        .cmd(&format!("ph entropy {} @ {}", size, name))
                        .ok()
                        .and_then(|v| v.trim().parse::<f32>().ok());
                    let function = BlockInfo {
                        name,
                        size,
                        ssdeep,
                        entropy,
                    };
                    self.zignatures.push(Zignature {
                        function,
                        bytes,
                        mask,
                        bbsum,
                        addr,
                        n_vars,
                    })
                }
            }
            _ => self.error.push("strings".to_string()),
        }
        self
    }

    fn anal_basic(&mut self, r2: &mut R2Pipe, yara_rules_file: String) {
        self.info(r2)
            .sha256(r2)
            .magic(r2)
            .imports(r2)
            .strings(r2)
            .sections(r2)
            .segments(r2)
            .links(r2)
            .yara(yara_rules_file);
    }

    fn anal_advanced(&mut self, r2: &mut R2Pipe) {
        self.zignatures(r2);
    }
}

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
