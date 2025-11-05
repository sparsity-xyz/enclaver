#!/usr/bin/env python3
"""
Parse Nitro Enclave attestation documents.

This script fetches an attestation document from the enclave API endpoint,
saves it as raw binary, and parses it into human-readable format.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def fetch_attestation(url: str, timeout: int = 10) -> bytes:
    """
    Fetch the attestation document from the API endpoint.
    
    Args:
        url: The full URL to the attestation endpoint
        timeout: Request timeout in seconds
        
    Returns:
        Raw binary CBOR attestation document
    """
    try:
        response = requests.post(
            url,
            json={},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"Error fetching attestation: {e}", file=sys.stderr)
        sys.exit(1)


def parse_certificate(cert_bytes: bytes) -> Dict[str, Any]:
    """
    Parse an X.509 certificate into a human-readable dictionary.
    
    Args:
        cert_bytes: DER-encoded certificate bytes
        
    Returns:
        Dictionary with parsed certificate fields
    """
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        
        subject = {}
        for attr in cert.subject:
            subject[attr.oid._name] = attr.value
            
        issuer = {}
        for attr in cert.issuer:
            issuer[attr.oid._name] = attr.value
        
        # Try to get fingerprint - handle different cryptography versions
        fingerprint_sha256 = None
        try:
            # Newer versions use hashes module
            from cryptography.hazmat.primitives import hashes
            fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        except (ImportError, AttributeError):
            try:
                # Older versions might have it directly
                fingerprint_sha256 = cert.fingerprint(x509.SHA256()).hex()
            except (AttributeError, TypeError):
                # Fallback: calculate manually or skip
                import hashlib
                fingerprint_sha256 = hashlib.sha256(cert_bytes).hexdigest()
            
        # Use UTC-aware datetime properties to avoid deprecation warnings
        try:
            not_valid_before = cert.not_valid_before_utc.isoformat()
            not_valid_after = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            # Fallback for older cryptography versions
            not_valid_before = cert.not_valid_before.isoformat()
            not_valid_after = cert.not_valid_after.isoformat()
        
        return {
            "subject": subject,
            "issuer": issuer,
            "serial_number": str(cert.serial_number),
            "not_valid_before": not_valid_before,
            "not_valid_after": not_valid_after,
            "fingerprint_sha256": fingerprint_sha256,
        }
    except Exception as e:
        return {"error": f"Failed to parse certificate: {e}", "raw": cert_bytes.hex()}


def parse_pcr(pcr_value: bytes) -> str:
    """
    Format PCR value as hex string.
    
    Args:
        pcr_value: PCR bytes
        
    Returns:
        Hex-formatted string
    """
    return pcr_value.hex() if pcr_value else "00" * 32


def parse_timestamp(timestamp_value) -> str:
    """
    Parse timestamp from bytes or int (Unix timestamp, may be in milliseconds).
    
    Args:
        timestamp_value: 8-byte big-endian timestamp bytes or int (seconds or milliseconds)
        
    Returns:
        ISO formatted datetime string
    """
    if isinstance(timestamp_value, int):
        # Check if it's in milliseconds (typically > 1e10)
        if timestamp_value > 1e10:
            timestamp_value = timestamp_value / 1000.0
        dt = datetime.fromtimestamp(timestamp_value)
        return dt.isoformat()
    elif isinstance(timestamp_value, bytes):
        if len(timestamp_value) == 8:
            timestamp = int.from_bytes(timestamp_value, byteorder="big")
            # Check if it's in milliseconds
            if timestamp > 1e10:
                timestamp = timestamp / 1000.0
            dt = datetime.fromtimestamp(timestamp)
            return dt.isoformat()
        return timestamp_value.hex()
    else:
        return str(timestamp_value)


def parse_attestation_doc(cbor_data: bytes) -> Dict[str, Any]:
    """
    Parse CBOR attestation document into human-readable format.
    
    Args:
        cbor_data: Raw CBOR bytes
        
    Returns:
        Parsed attestation document as dictionary
    """
    try:
        doc = cbor2.loads(cbor_data)
    except Exception as e:
        return {"error": f"Failed to parse CBOR: {e}"}
    
    if not isinstance(doc, list) or len(doc) < 4:
        return {"error": "Invalid attestation document structure", "raw": doc}
    
    version = doc[0] if len(doc) > 0 else None
    user_data_raw = doc[1] if len(doc) > 1 else {}
    nonce_raw = doc[2] if len(doc) > 2 else None
    certificate_raw = doc[3] if len(doc) > 3 else None
    
    # Handle version field - it might be bytes, string, or CBOR tag
    version_str = None
    if isinstance(version, bytes):
        try:
            version_str = version.decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            # If it's not UTF-8, use hex representation
            version_str = version.hex()
    else:
        version_str = str(version) if version is not None else None
    
    parsed = {
        "version": version_str,
    }
    
    # Check if nonce field actually contains user_data (CBOR-encoded)
    # This happens when user_data is passed as bytes to the NSM
    user_data_from_nonce = None
    if isinstance(nonce_raw, bytes):
        try:
            # Try to decode as CBOR - if it's a map, it's likely user_data
            decoded_nonce = cbor2.loads(nonce_raw)
            if isinstance(decoded_nonce, dict):
                user_data_from_nonce = decoded_nonce
            else:
                parsed["nonce"] = nonce_raw.hex()
        except Exception:
            # Not CBOR, treat as regular nonce
            parsed["nonce"] = nonce_raw.hex()
    elif nonce_raw and not isinstance(nonce_raw, dict):
        parsed["nonce"] = nonce_raw
    
    # Use user_data from nonce field if doc[1] is empty, otherwise use doc[1]
    if user_data_from_nonce is not None:
        user_data_raw = user_data_from_nonce
    
    if isinstance(user_data_raw, dict):
        parsed_user_data = {}
        
        for key, value in user_data_raw.items():
            if isinstance(key, bytes):
                try:
                    key_str = key.decode('utf-8')
                except UnicodeDecodeError:
                    key_str = key.hex()
            else:
                key_str = str(key)
            
            if key_str == "module_id":
                if isinstance(value, bytes):
                    try:
                        parsed_user_data["module_id"] = value.decode('utf-8')
                    except UnicodeDecodeError:
                        parsed_user_data["module_id"] = value.hex()
                else:
                    parsed_user_data["module_id"] = value
            elif key_str == "digest":
                if isinstance(value, bytes):
                    parsed_user_data["digest"] = {
                        "algorithm": "SHA384" if len(value) == 48 else "SHA256",
                        "value": value.hex()
                    }
                else:
                    parsed_user_data["digest"] = value
            elif key_str == "timestamp":
                parsed_user_data["timestamp"] = parse_timestamp(value)
            elif key_str == "pcrs":
                if isinstance(value, dict):
                    parsed_user_data["pcrs"] = {
                        str(k): {
                            "value": parse_pcr(v) if isinstance(v, bytes) else v.hex() if isinstance(v, bytes) else str(v),
                            "pcr_index": int(k) if isinstance(k, (int, str)) and str(k).isdigit() else k
                        }
                        for k, v in value.items()
                    }
                else:
                    parsed_user_data["pcrs"] = value.hex() if isinstance(value, bytes) else value
            elif key_str == "certificate":
                if isinstance(value, bytes):
                    try:
                        parsed_user_data["certificate"] = parse_certificate(value)
                    except Exception as e:
                        parsed_user_data["certificate"] = {
                            "error": f"Failed to parse certificate: {e}",
                            "raw": value.hex()
                        }
                else:
                    parsed_user_data["certificate"] = value.hex() if isinstance(value, bytes) else value
            elif key_str == "cabundle":
                if isinstance(value, list):
                    parsed_user_data["cabundle"] = []
                    for cert in value:
                        if isinstance(cert, bytes):
                            try:
                                parsed_user_data["cabundle"].append(parse_certificate(cert))
                            except Exception as e:
                                parsed_user_data["cabundle"].append({
                                    "error": f"Failed to parse certificate: {e}",
                                    "raw": cert.hex()
                                })
                        else:
                            parsed_user_data["cabundle"].append(cert.hex() if isinstance(cert, bytes) else cert)
                else:
                    parsed_user_data["cabundle"] = value.hex() if isinstance(value, bytes) else value
            elif key_str == "user_data":
                # user_data field - if 20 bytes, it's raw ETH address bytes, convert to hex string
                if isinstance(value, bytes):
                    if len(value) == 20:
                        # Raw 20-byte Ethereum address - convert to hex string with 0x prefix
                        parsed_user_data["user_data"] = "0x" + value.hex()
                    else:
                        # Try to decode as UTF-8 string (for backward compatibility)
                        try:
                            parsed_user_data["user_data"] = value.decode('utf-8')
                        except UnicodeDecodeError:
                            # If not UTF-8, return hex representation
                            parsed_user_data["user_data"] = value.hex()
                else:
                    parsed_user_data["user_data"] = value
            else:
                if isinstance(value, bytes):
                    parsed_user_data[key_str] = value.hex()
                else:
                    parsed_user_data[key_str] = value
        
        parsed["user_data"] = parsed_user_data
    elif isinstance(user_data_raw, bytes):
        # If 20 bytes, it's raw ETH address bytes, convert to hex string
        if len(user_data_raw) == 20:
            parsed["user_data"] = "0x" + user_data_raw.hex()
        else:
            # Try to decode as UTF-8 string (for backward compatibility)
            try:
                parsed["user_data"] = user_data_raw.decode('utf-8')
            except UnicodeDecodeError:
                # If not UTF-8, return hex representation
                parsed["user_data"] = user_data_raw.hex()
    else:
        parsed["user_data"] = user_data_raw
    
    # Handle certificate/signature field - could be bytes, list of bytes, or CBOR-encoded
    # In Nitro Enclave attestation docs, doc[3] is typically a signature (64-96 bytes), not a certificate
    if isinstance(certificate_raw, bytes):
        # If it's short (<= 128 bytes), it's likely a signature, not a certificate
        if len(certificate_raw) <= 128:
            parsed["signature"] = certificate_raw.hex()
        else:
            # Try to parse as certificate first
            try:
                parsed["certificate"] = parse_certificate(certificate_raw)
            except Exception:
                # If parsing fails, try decoding as CBOR (might be a list/bundle)
                try:
                    decoded_cert = cbor2.loads(certificate_raw)
                    if isinstance(decoded_cert, list):
                        parsed["certificate_bundle"] = []
                        for cert in decoded_cert:
                            if isinstance(cert, bytes):
                                try:
                                    parsed["certificate_bundle"].append(parse_certificate(cert))
                                except Exception as e:
                                    parsed["certificate_bundle"].append({
                                        "error": f"Failed to parse certificate: {e}",
                                        "raw": cert.hex()
                                    })
                            else:
                                parsed["certificate_bundle"].append(cert)
                    else:
                        parsed["certificate"] = {
                            "error": "Certificate field is not a valid certificate or bundle",
                            "raw": certificate_raw.hex()
                        }
                except Exception:
                    parsed["certificate"] = {
                        "error": "Failed to parse certificate",
                        "raw": certificate_raw.hex()
                    }
    elif isinstance(certificate_raw, list):
        parsed["certificate_bundle"] = []
        for cert in certificate_raw:
            if isinstance(cert, bytes):
                try:
                    parsed["certificate_bundle"].append(parse_certificate(cert))
                except Exception as e:
                    parsed["certificate_bundle"].append({
                        "error": f"Failed to parse certificate: {e}",
                        "raw": cert.hex()
                    })
            else:
                parsed["certificate_bundle"].append(cert.hex() if isinstance(cert, bytes) else cert)
    elif certificate_raw:
        parsed["certificate"] = certificate_raw.hex() if isinstance(certificate_raw, bytes) else certificate_raw
    
    if len(doc) > 4:
        public_key = doc[4] if len(doc) > 4 else None
        if public_key:
            parsed["public_key"] = public_key.hex() if isinstance(public_key, bytes) else public_key
    
    if len(doc) > 5:
        signature = doc[5] if len(doc) > 5 else None
        if signature:
            parsed["signature"] = signature.hex() if isinstance(signature, bytes) else signature
    
    return parsed


def main():
    parser = argparse.ArgumentParser(
        description="Fetch and parse Nitro Enclave attestation documents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch and parse attestation, save to attestation.report
  %(prog)s http://localhost:9000/v1/attestation
  
  # Specify output file
  %(prog)s http://localhost:9000/v1/attestation -o my_attestation.report
  
  # Parse existing attestation file
  %(prog)s -f attestation.report
  
  # Only save raw binary, don't parse
  %(prog)s http://localhost:9000/v1/attestation -o attestation.report --no-parse
        """,
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="URL of the attestation endpoint (e.g., http://localhost:9000/v1/attestation)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="attestation.report",
        help="Output file for raw binary attestation document (default: attestation.report)",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Parse an existing attestation file instead of fetching",
    )
    parser.add_argument(
        "--no-parse",
        action="store_true",
        help="Only save raw binary, don't parse",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    
    args = parser.parse_args()
    
    if args.file:
        if not Path(args.file).exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        cbor_data = Path(args.file).read_bytes()
    elif args.url:
        cbor_data = fetch_attestation(args.url, args.timeout)
    else:
        parser.print_help()
        sys.exit(1)
    
    if not args.no_parse:
        if args.file:
            output_file = args.file
        else:
            output_file = args.output
        
        output_path = Path(output_file)
        output_path.write_bytes(cbor_data)
        print(f"Saved raw attestation to: {output_path}", file=sys.stderr)
        
        parsed = parse_attestation_doc(cbor_data)
        
        # Ensure any remaining bytes are converted to strings for JSON output
        def convert_bytes_to_str(obj):
            if isinstance(obj, bytes):
                try:
                    return obj.decode('utf-8')
                except UnicodeDecodeError:
                    return obj.hex()
            elif isinstance(obj, dict):
                return {k: convert_bytes_to_str(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_bytes_to_str(item) for item in obj]
            else:
                return obj
        
        parsed = convert_bytes_to_str(parsed)
        print(json.dumps(parsed, indent=2))
    else:
        if args.file:
            print("Error: --no-parse requires a URL, not a file", file=sys.stderr)
            sys.exit(1)
        output_path = Path(args.output)
        output_path.write_bytes(cbor_data)
        print(f"Saved raw attestation to: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()

