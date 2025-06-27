from typing import Dict, Any
import json
import os
from ..exec_client import  CACHE_KEY_FILENAME


def _get_cached_result(key_hash: str, config: Dict[str, Any]):
    from conseq import helper

    remote = helper.new_remote(config["CLOUD_STORAGE_CACHE_ROOT"], None)
    results_path = os.path.join(
        config["CLOUD_STORAGE_CACHE_ROOT"], key_hash, "results.json"
    )
    if remote.exists(results_path):
        content = remote.download_as_str(results_path)
        assert isinstance(content, str)
        outputs = json.loads(content)
    else:
        outputs = None
    return results_path, outputs


def _read_cache_key(cache_key_path):
    with open(cache_key_path, "rt") as fd:
        cache_key = json.load(fd)
    canonical_key = json.dumps(cache_key, sort_keys=True)
    from hashlib import sha256

    key_hash = sha256(canonical_key.encode("utf8")).hexdigest()

    return key_hash, canonical_key


def _compute_cache_key_path(cache_key, config):
    assert isinstance(cache_key, dict)
    canonical_key = json.dumps(cache_key, sort_keys=True)
    from hashlib import sha256

    key_hash = sha256(canonical_key.encode("utf8")).hexdigest()
    return os.path.join(config["CLOUD_STORAGE_CACHE_ROOT"], key_hash), canonical_key


def _store_cached_result(
    cache_key: Dict, amended_outputs: Dict[str, Any], config: Dict[str, Any]
):
    assert isinstance(cache_key, dict)
    from conseq import helper

    remote = helper.new_remote(config["CLOUD_STORAGE_CACHE_ROOT"], None)

    cache_dir, canonical_key = _compute_cache_key_path(cache_key, config)

    dest_cache_key_path = os.path.join(cache_dir, CACHE_KEY_FILENAME)
    results_path = os.path.join(cache_dir, "results.json")

    remote.upload_str(dest_cache_key_path, canonical_key)
    remote.upload_str(results_path, json.dumps(amended_outputs))
