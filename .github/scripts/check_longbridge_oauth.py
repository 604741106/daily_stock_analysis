"""Protect headless SDK credentials and optionally verify Longbridge quotes."""

import argparse
import base64
import json
import os
import sys
from pathlib import Path


def validate_cache(raw: bytes, client_id: str) -> dict:
    cache = json.loads(raw)
    if not isinstance(cache, dict) or cache.get("client_id") != client_id:
        raise ValueError("OAuth cache does not match the configured client ID.")
    for name in ("access_token", "refresh_token"):
        if not isinstance(cache.get(name), str) or not cache[name]:
            raise ValueError("OAuth cache is missing a required token.")
    return cache


def mask(cache: dict) -> None:
    for name in ("access_token", "refresh_token"):
        escaped = cache[name].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::add-mask::{escaped}", flush=True)


def secret_box():
    from nacl.secret import SecretBox

    encoded_key = os.environ.get("LONGBRIDGE_OAUTH_CACHE_ENCRYPTION_KEY", "")
    key = base64.b64decode(encoded_key, validate=True)
    if len(key) != SecretBox.KEY_SIZE:
        raise ValueError("Configure a 32-byte OAuth cache encryption key in Secrets.")
    return SecretBox(key)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--mask-only", action="store_true")
    modes.add_argument("--prepare", action="store_true")
    modes.add_argument("--seal", action="store_true")
    parser.add_argument("--cache-path", type=Path)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Credential handling must run inside GitHub Actions.")
    client_id = os.environ.get("LONGBRIDGE_OAUTH_CLIENT_ID", "").strip()
    if not client_id:
        raise SystemExit("Configure the Longbridge OAuth client ID first.")
    sdk_cache = Path.home() / ".longbridge" / "openapi" / "tokens" / client_id

    try:
        if args.seal:
            if args.cache_path is None:
                raise ValueError("Encrypted cache path is required.")
            raw = sdk_cache.read_bytes()
            cache = validate_cache(raw, client_id)
            mask(cache)
            args.cache_path.parent.mkdir(parents=True, exist_ok=True)
            args.cache_path.write_bytes(bytes(secret_box().encrypt(raw)))
            print("Saved authenticated-encrypted Longbridge OAuth cache.")
            return

        encoded = os.environ.get("LONGBRIDGE_OAUTH_TOKEN_CACHE_B64", "").strip()
        raw = base64.b64decode(encoded, validate=True)
        seed = validate_cache(raw, client_id)
        mask(seed)
        if args.prepare:
            if args.cache_path is None:
                raise ValueError("Encrypted cache path is required.")
            box = secret_box()
            if args.cache_path.exists():
                raw = box.decrypt(args.cache_path.read_bytes())
                mask(validate_cache(raw, client_id))
            sdk_cache.parent.mkdir(parents=True, exist_ok=True)
            sdk_cache.write_bytes(raw)
            sdk_cache.chmod(0o600)
            from longbridge.openapi import OAuthBuilder

            def refuse_browser(_url):
                raise RuntimeError("OAuth refresh failed; renew the SDK cache Secret on an interactive computer.")

            OAuthBuilder(client_id).build(refuse_browser)
            raw = sdk_cache.read_bytes()
            mask(validate_cache(raw, client_id))
            encoded = base64.b64encode(raw).decode("ascii")
            print(f"::add-mask::{encoded}", flush=True)
            with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as handle:
                handle.write(f"LONGBRIDGE_OAUTH_TOKEN_CACHE_B64={encoded}\n")
            print("Prepared SDK OAuth cache without interactive authorization.")
            return
        if args.mask_only:
            return
    except (ValueError, UnicodeError, OSError) as error:
        raise SystemExit(f"Longbridge OAuth cache setup failed: {error}") from None

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from data_provider.longbridge_fetcher import LongbridgeFetcher, _to_longbridge_symbol

    stock = os.environ.get("STOCK_LIST", "").split(",")[0].strip()
    symbol = _to_longbridge_symbol(stock)
    if symbol is None:
        raise SystemExit("Quote verification requires a US or HK stock in STOCK_LIST.")
    context = LongbridgeFetcher()._get_ctx()
    if context is None or not context.quote([symbol]):
        raise SystemExit("Longbridge SDK OAuth quote verification failed.")
    print(f"Longbridge SDK OAuth quote verified: {symbol}")


if __name__ == "__main__":
    main()
