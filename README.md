# The openZign project
Zignatures and other binary identification data

# Indexing
First try with indexing with tantivy search.

## Facets
1. Level: Classification of the Binary Sample (Malware, Library, Various)
2. Level: CPU Architecture (x86, arm, ...)
3. Level: OS, lang, machine, format, bintype 

## Fields
* Strings, Links, Imports, Yara: `SimpleTokenizer` or `NgramTokenizer` with `MultiValues` Cardinality
* name, sha256, magic, size, error

## Zignatures, Segments, Sections
Indexed seperately. `MultiValues` field containing child document IDs.

### Zignatures
The masked zignature should be what you want to search for. It can be tokenized by using 
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
