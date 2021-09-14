use r2pipe::R2Pipe;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;
use tantivy::{doc, schema::*, Document};

#[derive(Deserialize, Serialize, Default)]
pub struct FileInfo {
    #[serde(skip_deserializing, skip_serializing)]
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
    pub fn new(path: String) -> Self {
        FileInfo {
            path: path.clone(),
            name: path.split('/').last().unwrap().to_string(),
            ..Default::default()
        }
    }

    pub fn sha256(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("itj") {
            Ok(json) => {
                self.sha256 = jstr(&json["sha256"]);
            }
            _ => self.error.push("sha256 hash".to_string()),
        }
        self
    }

    pub fn magic(&mut self, r2: &mut R2Pipe) -> &mut Self {
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

    pub fn info(&mut self, r2: &mut R2Pipe) -> &mut Self {
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

    pub fn strings(&mut self, r2: &mut R2Pipe) -> &mut Self {
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

    pub fn imports(&mut self, r2: &mut R2Pipe) -> &mut Self {
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

    pub fn sections(&mut self, r2: &mut R2Pipe) -> &mut Self {
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

    pub fn segments(&mut self, r2: &mut R2Pipe) -> &mut Self {
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

    pub fn links(&mut self, r2: &mut R2Pipe) -> &mut Self {
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

    pub fn yara(&mut self, yara_rules_file: String) -> &mut Self {
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

    pub fn zignatures(&mut self, r2: &mut R2Pipe) -> &mut Self {
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

    pub fn anal_basic(&mut self, r2: &mut R2Pipe, yara_rules_file: String) {
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

    pub fn anal_advanced(&mut self, r2: &mut R2Pipe) {
        self.zignatures(r2);
    }

    pub fn get_artifact(&self, schema: &Schema, origin: &str) -> Document {
        let mut result = Document::new();
        let facet_string = format!("/{}/{}/{}", origin, &self.arch, &self.os);
        result.add_facet(schema.get_field("category").unwrap(), &facet_string);
        result.add_text(schema.get_field("sha256").unwrap(), &self.sha256);
        result.add_text(schema.get_field("name").unwrap(), &self.name);
        result.add_u64(schema.get_field("size").unwrap(), self.size);
        let field = schema.get_field("magic").unwrap();
        for value in self.magic.iter() {
            result.add_text(field, &value);
        }
        let field = schema.get_field("strings").unwrap();
        for value in self.strings.iter() {
            result.add_text(field, &value);
        }
        let field = schema.get_field("links").unwrap();
        for value in self.links.iter() {
            result.add_text(field, &value);
        }
        let field = schema.get_field("imports").unwrap();
        for value in self.imports.iter() {
            result.add_text(field, &value.name);
        }
        let field = schema.get_field("yara").unwrap();
        for value in self.yara.split(' ') {
            result.add_text(field, &value);
        }
        result
    }

    pub fn get_zignatures(&self, schema: &Schema, origin: &str) -> Vec<Document> {
        let mut result = Vec::new();
        let facet_string = format!("/{}/{}/{}", origin, &self.arch, &self.os);
        let empty = String::new();
        for zign in self.zignatures.iter() {
            let mut doc = Document::new();
            doc.add_facet(schema.get_field("category").unwrap(), &facet_string);
            doc.add_text(schema.get_field("artifact_hash").unwrap(), &self.sha256);
            doc.add_text(schema.get_field("artifact_name").unwrap(), &self.name);
            doc.add_text(schema.get_field("name").unwrap(), &zign.function.name);
            doc.add_text(
                schema.get_field("ssdeep").unwrap(),
                zign.function.ssdeep.as_ref().unwrap_or(&empty),
            );
            doc.add_f64(
                schema.get_field("entropy").unwrap(),
                zign.function.entropy.unwrap_or_default() as f64,
            );
            doc.add_u64(schema.get_field("size").unwrap(), zign.function.size);
            doc.add_u64(schema.get_field("bbsum").unwrap(), zign.bbsum);
            doc.add_u64(schema.get_field("vars").unwrap(), zign.n_vars);

            let masked: String = zign
                .bytes
                .as_str()
                .chars()
                .zip(zign.mask.as_str().chars())
                .map(|(b, m)| if m == '0' { ' ' } else { b })
                .collect();
            doc.add_text(schema.get_field("masked").unwrap(), &masked);

            result.push(doc);
        }

        result
    }

    pub fn get_blocks(&self, schema: &Schema, origin: &str) -> Vec<Document> {
        let mut result = Vec::new();
        let facet_string = format!("/{}/{}/{}", origin, &self.arch, &self.os);
        let empty = String::new();

        let create_doc = |block: &BlockInfo| -> Document {
            let mut doc = Document::new();
            doc.add_facet(schema.get_field("category").unwrap(), &facet_string);
            doc.add_text(schema.get_field("artifact_hash").unwrap(), &self.sha256);
            doc.add_text(schema.get_field("artifact_name").unwrap(), &self.name);
            doc.add_text(schema.get_field("name").unwrap(), &block.name);
            doc.add_text(
                schema.get_field("ssdeep").unwrap(),
                block.ssdeep.as_ref().unwrap_or(&empty),
            );
            doc.add_f64(
                schema.get_field("entropy").unwrap(),
                block.entropy.unwrap_or_default() as f64,
            );
            doc.add_u64(schema.get_field("size").unwrap(), block.size);
            doc
        };

        for block in self.sections.iter() {
            result.push(create_doc(block));
        }

        for block in self.segments.iter() {
            result.push(create_doc(block));
        }

        result
    }
}
