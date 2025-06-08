# DUG - DNS Lookup Utility

[![Rust](https://img.shields.io/badge/rust-1.70%2B-brightgreen.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/workflow/status/blackstar257/dug/CI)](https://github.com/blackstar257/dug/actions)

A modern DNS lookup utility written in Rust that serves as a drop-in replacement for the traditional `dig` command. DUG provides fast, reliable DNS queries with a familiar interface and enhanced features.

## 🚀 Features

- **Full `dig` compatibility**: Supports the same command-line interface and output format
- **Multiple record types**: A, AAAA, MX, NS, SOA, TXT, CNAME, PTR, SRV, CAA, and more
- **Query classes**: IN (Internet), CH (Chaos), HS (Hesiod)
- **Advanced querying**:
  - Trace queries (`+trace`) for step-by-step resolution
  - Reverse DNS lookups (`-x`)
  - Batch file processing (`-f`)
  - TCP and UDP support
- **Flexible output**:
  - Short format (`+short`)
  - Customizable section display
  - Colored output for better readability
- **Network options**:
  - IPv4/IPv6 preference
  - Custom timeouts and retry logic
  - Source address binding
- **Performance**: Built with Rust for speed and memory safety
- **Cross-platform**: Works on Linux, macOS, and Windows

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/blackstar257/dug.git
cd dug

# Build and install
cargo build --release
cargo install --path .
```

### Using Cargo

```bash
cargo install dug
```

### Pre-built Binaries

Download the latest release from the [releases page](https://github.com/blackstar257/dug/releases).

## 🔧 Usage

### Basic Queries

```bash
# Query A record for a domain
dug example.com

# Query specific record type
dug example.com MX

# Query with specific DNS server
dug @8.8.8.8 example.com

# Short output format
dug +short example.com
```

### Advanced Queries

```bash
# Trace query path
dug +trace example.com

# Reverse DNS lookup
dug -x 8.8.8.8

# TCP query
dug +tcp example.com

# Query with timeout
dug +time=10 example.com

# IPv6 only
dug -6 example.com AAAA
```

### Batch Processing

```bash
# Process multiple queries from file
dug -f queries.txt
```

Example `queries.txt`:
```
example.com A
google.com MX
@8.8.8.8 cloudflare.com
+short reddit.com
```

### Output Control

```bash
# Hide specific sections
dug +noquestion +noauthority example.com

# Show only answers
dug +noall +answer example.com

# Disable comments
dug +nocomments example.com
```

## 📖 Command Line Options

### Flags

| Flag | Description |
|------|-------------|
| `-4` | Use IPv4 only |
| `-6` | Use IPv6 only |
| `-b ADDRESS` | Set source IP address |
| `-c CLASS` | Set query class (IN, CH, HS) |
| `-f FILENAME` | Read queries from batch file |
| `-h` | Show help information |
| `-k FILENAME` | TSIG key file |
| `-p PORT` | Set port number |
| `-q NAME` | Set query name |
| `-t TYPE` | Set query type |
| `-x ADDR` | Reverse lookup |
| `-y KEY` | TSIG key |

### Query Options

| Option | Description |
|--------|-------------|
| `+[no]tcp` | Use TCP instead of UDP |
| `+[no]short` | Short output format |
| `+[no]trace` | Trace delegation path |
| `+[no]recurse` | Enable/disable recursion |
| `+[no]dnssec` | Request DNSSEC validation |
| `+[no]question` | Show/hide question section |
| `+[no]answer` | Show/hide answer section |
| `+[no]authority` | Show/hide authority section |
| `+[no]additional` | Show/hide additional section |
| `+[no]stats` | Show/hide query statistics |
| `+[no]cmd` | Show/hide command line |
| `+[no]comments` | Show/hide comment lines |
| `+time=N` | Set timeout in seconds |
| `+tries=N` | Set number of tries |
| `+retry=N` | Set number of retries |

## 🌟 Examples

### Common DNS Queries

```bash
# Check if a website is accessible
dug +short example.com A

# Find mail servers
dug example.com MX

# Check nameservers
dug example.com NS

# Get all DNS records
dug example.com ANY

# Check reverse DNS
dug -x 192.168.1.1
```

### Troubleshooting DNS

```bash
# Trace full resolution path
dug +trace example.com

# Check specific DNS server response
dug @1.1.1.1 example.com

# Test with TCP (useful for large responses)
dug +tcp example.com TXT

# Check DNSSEC validation
dug +dnssec example.com
```

## 🛠️ Development

### Prerequisites

- Rust 1.70 or later
- Cargo

### Building

```bash
git clone https://github.com/blackstar257/dug.git
cd dug
cargo build
```

### Testing

```bash
cargo test
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

This project uses standard Rust formatting. Run the following before submitting:

```bash
cargo fmt
cargo clippy
```

## 📝 Dependencies

- **trust-dns-resolver**: DNS resolution library
- **trust-dns-proto**: DNS protocol implementation
- **clap**: Command-line argument parsing
- **tokio**: Async runtime
- **anyhow**: Error handling
- **chrono**: Date and time handling
- **colored**: Terminal output coloring

## 🔍 Comparison with `dig`

| Feature | dig | dug | Notes |
|---------|-----|-----|-------|
| Basic queries | ✅ | ✅ | Full compatibility |
| Record types | ✅ | ✅ | All common types supported |
| Trace queries | ✅ | ✅ | Step-by-step resolution |
| Batch files | ✅ | ✅ | Process multiple queries |
| Output formats | ✅ | ✅ | Short and full formats |
| Performance | ⚡ | ⚡⚡ | Rust provides better performance |
| Memory usage | 📊 | 📉 | Lower memory footprint |
| Cross-platform | ✅ | ✅ | Works on all major platforms |

## 🐛 Known Issues

- AXFR (zone transfer) queries are not yet implemented
- Some advanced TSIG features are in development

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by the original `dig` utility from ISC BIND
- Built with the excellent Rust DNS libraries from the trust-dns project
- Thanks to the Rust community for their amazing ecosystem

## 📞 Support

- 🐛 **Bug Reports**: [Issues](https://github.com/blackstar257/dug/issues)
- 💡 **Feature Requests**: [Discussions](https://github.com/blackstar257/dug/discussions)
- 📧 **Email**: your-email@example.com

---

**DUG** - Making DNS queries fast, reliable, and modern with Rust 🦀 