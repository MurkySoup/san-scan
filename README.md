# san-scan (TLS Certificate CN/SAN Inspector)

A lightweight Python utility for retrieving and inspecting the TLS certificate presented by a remote server.

The tool reports the certificate's **Common Name (CN)** and **Subject Alternative Names (SANs)** without requiring the certificate to be trusted or valid. This makes it useful for security assessments, certificate inventories, and troubleshooting TLS configurations.

## Features

* Retrieves certificates using TLS Server Name Indication (SNI).
* Extracts the certificate Common Name (CN).
* Extracts Subject Alternative Names (SANs).
* Supports DNS, IP address, URI, and other SAN types.
* Supports custom TLS ports.
* Configurable network timeout.
* Human-readable or JSON output.
* Uses Python's standard `ssl` and `socket` modules for networking.
* Uses `cryptography` for X.509 certificate parsing.
* No logging framework or external command-line dependencies.

## Requirements

* Python 3.11+
* `cryptography`

Install dependencies:

```bash
pip3 install -r requirements.txt
```

## Usage

Inspect a standard HTTPS site:

```bash
python3 san-scan.py example.com
```

Specify a custom port:

```bash
python3 san-scan.py example.com:8443
```

URLs are also accepted:

```bash
python3 san-scan.py https://example.com
```

Increase the network timeout:

```bash
python3 san-scan.py example.com --timeout 30
```

Produce machine-readable JSON:

```bash
python3 san-scan.py example.com --json
```

Example:

```text
Host: example.com
Port: 443
CN: example.com
SAN: example.com, www.example.com
```

## Certificate Validation

Certificate trust validation is intentionally **disabled**.

The purpose of this utility is to determine which certificate a server presents, including certificates that are expired, self-signed, incorrectly configured, or otherwise untrusted. This behavior is useful when performing certificate and TLS security assessments.

Consequently, a successful result does **not** indicate that the certificate is trusted or valid.

## Exit Codes

| Code | Meaning                                                                         |
| ---: | ------------------------------------------------------------------------------- |
|  `0` | Certificate successfully retrieved and parsed                                   |
|  `1` | Invalid target, connection failure, TLS failure, or certificate parsing failure |

## License

See the repository's license file for licensing terms.

## Built With

* [Python](https://www.python.org) designed by Guido van Rossum

## Author

**Rick Pelletier** - galiagante@gmail.com

