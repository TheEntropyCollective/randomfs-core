# RandomFS Core Library

A modern Go implementation of the Owner Free File System (OFFS) concept, providing a library for storing and retrieving files using randomized blocks on IPFS.

## Overview

RandomFS Core is a pure Go library that implements the Owner Free File System concept. Files are split into randomized blocks that appear as noise, providing deniability while maintaining the ability to reconstruct original files using rd:// URLs.

## Features

- **Multi-tier Block Sizing**: Automatically selects optimal block sizes (1KB, 64KB, 1MB) based on file size
- **XOR-based Randomization**: Blocks are randomized using XOR operations for deniability
- **IPFS Integration**: Uses IPFS HTTP API for decentralized storage
- **LRU Caching**: Efficient block caching with configurable size limits
- **rd:// URL Scheme**: Decentralized file access using custom URL format
- **Pure Go Library**: No external dependencies beyond standard library and IPFS API

## Installation

```bash
go get github.com/TheEntropyCollective/randomfs-core
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "github.com/TheEntropyCollective/randomfs-core"
)

func main() {
    // Initialize RandomFS with IPFS API endpoint
    rfs, err := randomfs.NewRandomFS("http://localhost:5001", "./data", 500*1024*1024)
    if err != nil {
        log.Fatal(err)
    }

    // Store a file
    rdURL, err := rfs.StoreFile("example.txt", "text/plain")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("File stored: %s\n", rdURL)

    // Retrieve a file
    data, contentType, err := rfs.RetrieveFile(rdURL)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Retrieved: %s (%s)\n", string(data), contentType)
}
```

## API Reference

### NewRandomFS(ipfsAPI, dataDir string, cacheSize int64) (*RandomFS, error)

Creates a new RandomFS instance.

- `ipfsAPI`: IPFS HTTP API endpoint (e.g., "http://localhost:5001")
- `dataDir`: Directory for local data storage
- `cacheSize`: Cache size in bytes

### StoreFile(filePath, contentType string) (string, error)

Stores a file and returns its rd:// URL.

- `filePath`: Path to the file to store
- `contentType`: MIME type of the file
- Returns: rd:// URL for file retrieval

### RetrieveFile(rdURL string) ([]byte, string, error)

Retrieves a file using its rd:// URL.

- `rdURL`: rd:// URL of the file to retrieve
- Returns: file data, content type, and error

### GetStats() Stats

Returns current system statistics.

## Block Sizing Strategy

RandomFS uses a multi-tier approach for optimal performance:

- **Small files (< 1MB)**: 1KB blocks
- **Medium files (1MB - 64MB)**: 64KB blocks  
- **Large files (> 64MB)**: 1MB blocks

## rd:// URL Format

Files are accessed using the rd:// URL scheme:

```
rd://<representation-hash>/<content-type>/<original-filename>
```

Example: `rd://QmX...abc/text/plain/example.txt`

## Dependencies

- Go 1.21+
- IPFS node (Kubo) with HTTP API enabled

## Development

```bash
# Run tests
go test -v

# Build library
go build

# Check dependencies
go mod tidy
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Related Projects

- [randomfs-cli](https://github.com/TheEntropyCollective/randomfs-cli) - Command-line interface
- [randomfs-http](https://github.com/TheEntropyCollective/randomfs-http) - HTTP server
- [randomfs-web](https://github.com/TheEntropyCollective/randomfs-web) - Web interface 