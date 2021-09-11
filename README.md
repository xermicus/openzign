# The openZign project
Zignatures and other binary identification data

# Indexing
First try with indexing with tantivy search.

## Facets
1. Level: Classification of the Binary Sample (Malware, Library, Various)
2. Level: CPU Architecture (x86, arm, ...)
3. Level: OS, lang, machine, format, bintype 

## Fields
* Strings, Links, Imports, Yara: `Default` indexer
* name, sha256, magic, size, error

## Zignatures, Segments, Sections
Indexed seperately. `MultiValues` field containing child document IDs.

### Zignatures
The masked zignature should be what you want to search for. Whether it's better to just split at the mask bytes and use `SimpleTokenizer` or strip them off 

* Name
* Size
* ssdeep
* Entropy
* bytes
* mask
* masked
* bbsum
* vars

### Segments & Sections
* Name
* ssdeep
* entropy
* size

# More ideas
* Index ESIL and assembly
* Do more konwn-good collections
  * Statically compiled languages (Rust, Golang) stdlibs and common modules
  * Windwos stuff
  * https://github.com/SoftSec-KAIST/BinKit
* Use KV store (rkv/tikv/sled) for documents and use tantivy only for search index
