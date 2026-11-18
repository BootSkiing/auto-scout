"""Package init.

Make HTTP clients (requests / urllib) trust the operating system's CA store
instead of only the `certifi` bundle that ships with `requests`.

This matters on networks behind a TLS-inspecting proxy (e.g. Zscaler), where
the server certificate is re-signed by a private corporate root. That root is
installed in the OS trust store (so `curl` works) but is absent from `certifi`,
which causes `SSLError: unable to get local issuer certificate`.

We locate the OS bundle via the stdlib (OpenSSL's default verify paths, so no
distro-specific path is hardcoded) and expose it to requests/urllib through the
standard env vars. `setdefault` keeps any value the operator set explicitly.
"""
import os
import ssl


def _use_system_trust_store() -> None:
    try:
        paths = ssl.get_default_verify_paths()
        bundle = paths.cafile or paths.openssl_cafile
        if bundle and os.path.exists(bundle):
            # requests reads these per-request in merge_environment_settings.
            os.environ.setdefault("REQUESTS_CA_BUNDLE", bundle)
            os.environ.setdefault("SSL_CERT_FILE", bundle)
    except Exception:
        # Never block startup over trust-store discovery; fall back to defaults.
        pass


_use_system_trust_store()
