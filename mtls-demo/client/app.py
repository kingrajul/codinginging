import json
import os
import subprocess
import time
from datetime import datetime, timezone

import requests
from cryptography import x509
from cryptography.x509 import NameOID, ExtensionNotFound
from cryptography.x509 import BasicConstraints, SubjectAlternativeName, KeyUsage, ExtendedKeyUsage
from cryptography.x509 import DNSName, IPAddress
from flask import Flask, jsonify, render_template

app = Flask(__name__)

SERVER_HOST = os.environ.get("SERVER_HOST", "mtls-server")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "443"))
SERVER_URL  = f"https://{SERVER_HOST}:{SERVER_PORT}"

CERTS_DIR   = os.environ.get("CERTS_DIR", "/app/certs")
CA_CERT     = os.path.join(CERTS_DIR, "ca",     "ca.crt")
SERVER_CERT = os.path.join(CERTS_DIR, "server", "server.crt")
CLIENT_CERT = os.path.join(CERTS_DIR, "client", "client.crt")
CLIENT_KEY  = os.path.join(CERTS_DIR, "client", "client.key")


# ── Certificate parsing ────────────────────────────────────────────────────────

def _name_field(name, oid):
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except (IndexError, Exception):
        return None


def parse_cert(path):
    try:
        with open(path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        subj = cert.subject
        issr = cert.issuer

        # Validity — use timezone-aware datetimes (cryptography >= 42)
        try:
            not_before = cert.not_valid_before_utc
            not_after  = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)

        days_left = (not_after - datetime.now(timezone.utc)).days

        # Subject Alternative Names
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
            for s in san_ext.value:
                if isinstance(s, DNSName):
                    sans.append(f"DNS:{s.value}")
                elif isinstance(s, IPAddress):
                    sans.append(f"IP:{s.value}")
        except ExtensionNotFound:
            pass

        # Key usage flags
        key_usage_list = []
        try:
            ku = cert.extensions.get_extension_for_class(KeyUsage).value
            for flag in ("digital_signature", "key_encipherment", "data_encipherment",
                         "key_agreement", "key_cert_sign", "crl_sign"):
                try:
                    if getattr(ku, flag, False):
                        key_usage_list.append(flag.replace("_", " ").title())
                except Exception:
                    pass
        except ExtensionNotFound:
            pass

        # Extended key usage
        ext_key_usage_list = []
        try:
            eku = cert.extensions.get_extension_for_class(ExtendedKeyUsage).value
            oid_names = {
                "1.3.6.1.5.5.7.3.1": "serverAuth",
                "1.3.6.1.5.5.7.3.2": "clientAuth",
            }
            for u in eku:
                ext_key_usage_list.append(oid_names.get(u.dotted_string, u.dotted_string))
        except ExtensionNotFound:
            pass

        # Is this a CA cert?
        is_ca = False
        try:
            bc = cert.extensions.get_extension_for_class(BasicConstraints)
            is_ca = bc.value.ca
        except ExtensionNotFound:
            pass

        return {
            "subject": {
                "CN": _name_field(subj, NameOID.COMMON_NAME),
                "O":  _name_field(subj, NameOID.ORGANIZATION_NAME),
                "OU": _name_field(subj, NameOID.ORGANIZATIONAL_UNIT_NAME),
                "C":  _name_field(subj, NameOID.COUNTRY_NAME),
                "ST": _name_field(subj, NameOID.STATE_OR_PROVINCE_NAME),
                "L":  _name_field(subj, NameOID.LOCALITY_NAME),
                "emailAddress": _name_field(subj, NameOID.EMAIL_ADDRESS),
            },
            "issuer": {
                "CN": _name_field(issr, NameOID.COMMON_NAME),
                "O":  _name_field(issr, NameOID.ORGANIZATION_NAME),
            },
            "serial":            format(cert.serial_number, "x").upper(),
            "version":           f"v{cert.version.value + 1}",
            "not_before":        not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "not_after":         not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_remaining":    days_left,
            "sig_algorithm":     cert.signature_hash_algorithm.name.upper()
                                 if cert.signature_hash_algorithm else "Unknown",
            "sans":              sans,
            "key_usage":         key_usage_list,
            "ext_key_usage":     ext_key_usage_list,
            "is_ca":             is_ca,
        }
    except FileNotFoundError:
        return {"error": f"File not found: {path}"}
    except Exception as e:
        return {"error": str(e)}


# ── Page routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/handshake")
def handshake():
    return render_template("handshake.html")

@app.route("/test")
def test():
    return render_template("test.html")

@app.route("/certs")
def certs_page():
    return render_template("certs.html")

@app.route("/openssl")
def openssl_page():
    return render_template("openssl.html")


# ── API routes ─────────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    status = {
        "certs": {
            "ca":          os.path.exists(CA_CERT),
            "server":      os.path.exists(SERVER_CERT),
            "client_cert": os.path.exists(CLIENT_CERT),
            "client_key":  os.path.exists(CLIENT_KEY),
        }
    }
    status["certs_ready"] = all(status["certs"].values())

    try:
        r = requests.get(
            f"{SERVER_URL}/api/cert-info",
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=CA_CERT,
            timeout=4,
        )
        status["server_reachable"] = True
        status["server_cert_info"] = r.json()
    except Exception as e:
        status["server_reachable"] = False
        status["server_error"]     = str(e)

    return jsonify(status)


@app.route("/api/connect-with-cert")
def api_connect_with_cert():
    t0 = time.perf_counter()
    try:
        r = requests.get(
            f"{SERVER_URL}/api/cert-info",
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=CA_CERT,
            timeout=6,
        )
        elapsed = round((time.perf_counter() - t0) * 1000)
        return jsonify({
            "success":        True,
            "cert_presented": True,
            "status_code":    r.status_code,
            "elapsed_ms":     elapsed,
            "server_data":    r.json(),
            "tls_headers": {
                k: v for k, v in r.headers.items()
                if k.startswith("X-")
            },
        })
    except requests.exceptions.SSLError as e:
        return jsonify({"success": False, "cert_presented": True,
                        "error": "SSL Error", "detail": str(e)})
    except Exception as e:
        return jsonify({"success": False, "cert_presented": True,
                        "error": type(e).__name__, "detail": str(e)})


@app.route("/api/connect-without-cert")
def api_connect_without_cert():
    t0 = time.perf_counter()
    try:
        r = requests.get(
            f"{SERVER_URL}/api/cert-info",
            verify=CA_CERT,   # no cert=(...) — intentionally omitting client cert
            timeout=6,
        )
        elapsed = round((time.perf_counter() - t0) * 1000)
        return jsonify({
            "success":        True,
            "cert_presented": False,
            "status_code":    r.status_code,
            "elapsed_ms":     elapsed,
            "note":           "Server accepted without client cert — mTLS may not be enforced!",
        })
    except requests.exceptions.SSLError as e:
        elapsed = round((time.perf_counter() - t0) * 1000)
        return jsonify({
            "success":        False,
            "cert_presented": False,
            "elapsed_ms":     elapsed,
            "expected":       True,   # this IS the correct mTLS behaviour
            "error":          "SSL handshake rejected — server refused connection (no client cert)",
            "detail":         str(e),
        })
    except Exception as e:
        return jsonify({"success": False, "cert_presented": False,
                        "error": type(e).__name__, "detail": str(e)})


@app.route("/api/cert-details")
def api_cert_details():
    return jsonify({
        "ca":     parse_cert(CA_CERT),
        "server": parse_cert(SERVER_CERT),
        "client": parse_cert(CLIENT_CERT),
    })


@app.route("/api/openssl-trace")
def api_openssl_trace():
    if not all(os.path.exists(p) for p in [CLIENT_CERT, CLIENT_KEY, CA_CERT]):
        return jsonify({"error": "Certificates not found"}), 500

    try:
        result = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"{SERVER_HOST}:{SERVER_PORT}",
                "-cert",   CLIENT_CERT,
                "-key",    CLIENT_KEY,
                "-CAfile", CA_CERT,
                "-state",                 # show SSL state machine transitions
                "-verify_return_error",
                "-brief",                 # compact handshake summary
            ],
            input=b"GET /api/cert-info HTTP/1.0\r\nHost: mtls-server\r\n\r\n",
            capture_output=True,
            timeout=10,
            text=True,
        )
        return jsonify({
            "stdout":     result.stdout,
            "stderr":     result.stderr,
            "returncode": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "openssl command timed out"}), 504
    except FileNotFoundError:
        return jsonify({"error": "openssl not found in container"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/openssl-trace-no-cert")
def api_openssl_trace_no_cert():
    try:
        result = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"{SERVER_HOST}:{SERVER_PORT}",
                "-CAfile", CA_CERT,
                "-state",
                "-brief",
            ],
            input=b"",
            capture_output=True,
            timeout=8,
            text=True,
        )
        return jsonify({
            "stdout":     result.stdout,
            "stderr":     result.stderr,
            "returncode": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)
