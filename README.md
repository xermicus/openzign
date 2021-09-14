# The openZign project
Zignatures and other binary identification database, to aid reverse-engineering tasks. Collected from various datasources:
* [x] [vx-underground collection](https://vx-underground.org/samples.html) (>2TB decompressed)
* [x] [BinKit](https://github.com/SoftSec-KAIST/BinKit) dataset (>200GB decompressed)
* [ ] Std-libs from statically compiled languages (golang, rust)
* [ ] Benign windows binaries
* [ ] ?

Note: This is still under heavy development. This README serves primarly to organize my thoughts.

# Project Structure
## oz-fila
Helper util to mass-analyse binary artifacts (exes, libraries, ...) from a directory. Result is one JSON file per binary containing analysis information from radare2.

## oz-indexer
Helper util to index and search the JSON files created by `oz-fila`.

## oz-api
Since the index get quite big, the final goal will be to provide some kind of http/rest API. (Reminds of IDA Lumina Server)

## (TODO) r2 plugin
Provide r2 plugin for convenience.

# Indexing
First try with indexing with tantivy search. It looks like it can handle large data volumes quite well.

Indexing is not yet continuous / automated (it literally takes weeks to analyze and index everything on my consumer grade desktop hardware).

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

# Ideas and Todos 
* Index ESIL and assembly (how to avoid duplicates with what is already in zignatures?)
* Use KV store (rkv/tikv/sled) for documents and use tantivy only for search index
* Some improvements:
  * Add a timestamp to see when the document was indexed
  * Handle "special" cases (Code inside APK, unpack packed samples)
  * Collect whole binary code instead only code recognized as function (zaF)
* Proper documentation
* Tweak user experience (simple default search query probably doesnt provide good results)