#!/usr/bin/env python3
"""Download a pretrained checkpoint and re-export it as plain safetensors.

This is the only Python in the conversion path, and it exists for one reason:
the checkpoint the ecosystem publishes is a pickled `pytorch_model.bin`, which
cannot be read without a PyTorch unpickler. Everything downstream of this
script — the BXW1 and BXV1 emission, the quantization, the digests — is Rust
with no external crate.

The tensors are written **as `f32`** so the Rust converter never has to
interpret a `bf16` or `f16` bit pattern: the widening is exact in both cases,
so nothing is lost by doing it here.

Usage:
    python3 fetch.py <model-id> <output-dir>
"""

import json
import shutil
import struct
import sys
from pathlib import Path


def export_safetensors(state, destination):
    """Write `state` (a dict of name -> torch f32 tensor) as a safetensors file."""
    header = {}
    offset = 0
    payloads = []
    for name in sorted(state):
        tensor = state[name].to(dtype=__import__("torch").float32).contiguous()
        raw = tensor.numpy().tobytes()
        header[name] = {
            "dtype": "F32",
            "shape": list(tensor.shape),
            "data_offsets": [offset, offset + len(raw)],
        }
        offset += len(raw)
        payloads.append(raw)
    encoded = json.dumps(header, separators=(",", ":")).encode("utf-8")
    padding = (-len(encoded)) % 8
    encoded += b" " * padding
    with open(destination, "wb") as handle:
        handle.write(struct.pack("<Q", len(encoded)))
        handle.write(encoded)
        for raw in payloads:
            handle.write(raw)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    model_id, output = sys.argv[1], Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)

    import torch
    from huggingface_hub import hf_hub_download

    wanted = ["config.json", "tokenizer_config.json", "vocab.json", "merges.txt"]
    for name in wanted:
        shutil.copyfile(hf_hub_download(model_id, name), output / name)

    try:
        weights = hf_hub_download(model_id, "model.safetensors")
        shutil.copyfile(weights, output / "model.safetensors")
        print("copied model.safetensors verbatim")
    except Exception:
        checkpoint = hf_hub_download(model_id, "pytorch_model.bin")
        state = torch.load(checkpoint, map_location="cpu", weights_only=True)
        export_safetensors(state, output / "model.safetensors")
        print("re-exported pytorch_model.bin as f32 safetensors")

    for name in sorted((output).iterdir()):
        print(f"  {name.name}  {name.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
