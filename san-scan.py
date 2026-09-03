#!/usr/bin/env python3
# Linter: ruff check san-scan.py --extend-select F,B,UP


"""
Retrieve the Common Name and Subject Alternative Names from a TLS certificate.

The certificate is retrieved directly from the specified TLS endpoint using
Server Name Indication (SNI). Certificate trust validation is intentionally
disabled by default because the purpose of this utility is certificate
inspection, including inspection of expired, self-signed, or otherwise
untrusted certificates.

Python: 3.11+
"""


from __future__ import annotations
import argparse
import ipaddress
import json
import socket
import ssl
import sys
from dataclasses import asdict, dataclass
from collections.abc import Sequence
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509.oid import NameOID


DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10.0


class CertificateInspectionError(Exception):
    """Represent an error encountered while inspecting a TLS certificate."""


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """Represent the relevant information extracted from an X.509 certificate."""

    host: str
    port: int
    common_name: str | None
    subject_alternative_names: list[str]


def parse_target(target: str) -> tuple[str, int]:
    """Parse a hostname, hostname:port, or URL into host and port.

    Args:
        target: Hostname, host/port combination, or HTTP(S) URL.

    Returns:
        A tuple containing the hostname and TCP port.

    Raises:
        ValueError: If the target is malformed or contains an invalid port.
    """
    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    # urlparse requires a scheme to reliably distinguish host:port syntax
    # from other forms.
    if "://" not in target:
        parsed = urlparse(f"//{target}", allow_fragments=False)
    else:
        parsed = urlparse(target, allow_fragments=False)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError(
                f"Unsupported URL scheme: {parsed.scheme!r}. "
                "Use http:// or https://."
            )

    if not parsed.hostname:
        raise ValueError(f"Unable to determine hostname from target: {target!r}")

    host = parsed.hostname

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Target contains an invalid port.") from exc

    if port is None:
        port = DEFAULT_PORT

    if not 1 <= port <= 65535:
        raise ValueError(f"Port must be between 1 and 65535: {port}")

    return host, port


def create_ssl_context() -> ssl.SSLContext:
    """Create an SSL context suitable for certificate inspection.

    Certificate verification is deliberately disabled. The utility needs to
    inspect certificates that may be expired, self-signed, or otherwise
    untrusted. Disabling verification is limited to certificate retrieval and
    does not provide authentication of the remote endpoint.

    Returns:
        A configured SSL context.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return context


def retrieve_certificate(
    host: str,
    port: int,
    timeout: float,
) -> bytes:
    """Retrieve the DER-encoded peer certificate from a TLS endpoint.

    Args:
        host: Remote hostname.
        port: Remote TCP port.
        timeout: Socket connection and TLS handshake timeout in seconds.

    Returns:
        The peer certificate in DER encoding.

    Raises:
        CertificateInspectionError: If DNS resolution, TCP connection, TLS
            negotiation, or certificate retrieval fails.
    """
    context = create_ssl_context()

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as tcp_socket:
            with context.wrap_socket(
                tcp_socket,
                server_hostname=host,
            ) as tls_socket:
                certificate = tls_socket.getpeercert(binary_form=True)

    except socket.gaierror as exc:
        raise CertificateInspectionError(
            f"DNS resolution failed for {host!r}: {exc}"
        ) from exc
    except socket.timeout as exc:
        raise CertificateInspectionError(
            f"Connection to {host}:{port} timed out after {timeout:g} seconds."
        ) from exc
    except ConnectionRefusedError as exc:
        raise CertificateInspectionError(
            f"Connection refused by {host}:{port}."
        ) from exc
    except ssl.SSLError as exc:
        raise CertificateInspectionError(
            f"TLS negotiation failed for {host}:{port}: {exc}"
        ) from exc
    except OSError as exc:
        raise CertificateInspectionError(
            f"Connection to {host}:{port} failed: {exc}"
        ) from exc

    if not certificate:
        raise CertificateInspectionError(
            f"The TLS endpoint {host}:{port} did not provide a certificate."
        )

    return certificate


def format_san_value(value: object) -> str:
    """Convert an X.509 SAN value to a predictable string representation.

    Args:
        value: SAN value returned by the cryptography library.

    Returns:
        A string representation of the SAN value.
    """
    if isinstance(value, ipaddress.IPv4Address | ipaddress.IPv6Address):
        return str(value)

    return str(value)


def extract_certificate_info(
    certificate_der: bytes,
    host: str,
    port: int,
) -> CertificateInfo:
    """Extract the CN and SAN values from a DER-encoded certificate.

    Args:
        certificate_der: DER-encoded X.509 certificate.
        host: Hostname used to retrieve the certificate.
        port: TCP port used to retrieve the certificate.

    Returns:
        A CertificateInfo instance containing the certificate identity data.

    Raises:
        CertificateInspectionError: If the certificate cannot be parsed.
    """
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise CertificateInspectionError(
            "The server returned data that is not a valid X.509 certificate."
        ) from exc

    common_name: str | None = None

    common_names = certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )

    if common_names:
        common_name = common_names[0].value

    san_values: list[str] = []

    try:
        san_extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        san_extension = None

    if san_extension is not None:
        for general_name in san_extension.value:
            san_values.append(format_san_value(general_name.value))

    return CertificateInfo(
        host=host,
        port=port,
        common_name=common_name,
        subject_alternative_names=san_values,
    )


def inspect_target(target: str, timeout: float) -> CertificateInfo:
    """Retrieve and inspect the TLS certificate for a target.

    Args:
        target: Hostname, hostname/port, or HTTP(S) URL.
        timeout: Network timeout in seconds.

    Returns:
        Extracted certificate identity information.

    Raises:
        ValueError: If the target is malformed.
        CertificateInspectionError: If certificate retrieval or parsing fails.
    """
    host, port = parse_target(target)
    certificate_der = retrieve_certificate(host, port, timeout)

    return extract_certificate_info(
        certificate_der,
        host,
        port,
    )


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Retrieve the Common Name (CN) and Subject Alternative Names "
            "(SAN) from a site's TLS certificate."
        )
    )

    parser.add_argument(
        "target",
        help=(
            "Target hostname, hostname:port, or HTTP(S) URL. "
            "Examples: example.com, example.com:8443, "
            "https://example.com"
        ),
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT:g}).",
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON.",
    )

    return parser


def print_human_readable(info: CertificateInfo) -> None:
    """Print certificate identity information in human-readable form.

    Args:
        info: Certificate information to display.
    """
    print(f"Host: {info.host}")
    print(f"Port: {info.port}")
    print(f"CN: {info.common_name or '(not present)'}")

    print("SAN: ", end="" )

    if info.subject_alternative_names:
        print(",".join(info.subject_alternative_names))
    else:
        print("(not present)")



def print_json(info: CertificateInfo) -> None:
    """Print certificate identity information as JSON.

    Args:
        info: Certificate information to serialize.
    """
    print(
        json.dumps(
            asdict(info),
            indent=2,
            sort_keys=True,
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Execute the command-line application.

    Args:
        argv: Optional command-line argument sequence. If omitted, arguments
            are read from sys.argv.

    Returns:
        Process exit status. Zero indicates success.
    """
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("Timeout must be greater than zero.")

    try:
        certificate_info = inspect_target(
            args.target,
            args.timeout,
        )
    except (ValueError, CertificateInspectionError) as exc:
        print(f"Error: {args.target} - {exc}")

        return 1

    if args.json_output:
        print_json(certificate_info)
    else:
        print_human_readable(certificate_info)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# end of script
