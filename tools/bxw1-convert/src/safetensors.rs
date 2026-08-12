//! A reader for the safetensors container.
//!
//! The format is eight little-endian bytes of header length, that many bytes of
//! JSON, then one contiguous payload region the header's `data_offsets` index.
//! Nothing about it needs a library.
//!
//! Only `F32` payloads are accepted. `fetch.py` widens whatever the checkpoint
//! stored to `f32` before writing, so a narrower dtype reaching here means the
//! export step was skipped, and guessing at a `bf16` bit pattern is exactly the
//! kind of silent reinterpretation the BXW1 spec refuses elsewhere.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::json;

/// One tensor's location and shape inside the payload region.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Axis extents, outermost first.
    pub shape: Vec<u64>,
    /// Payload-relative start.
    pub start: u64,
    /// Payload-relative end.
    pub end: u64,
}

impl Entry {
    /// Product of the extents.
    pub fn elements(&self) -> u64 {
        self.shape.iter().product()
    }
}

/// An open safetensors file.
pub struct SafeTensors {
    file: File,
    payload_base: u64,
    entries: BTreeMap<String, Entry>,
}

impl SafeTensors {
    /// Opens the file and decodes its header.
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut length = [0u8; 8];
        file.read_exact(&mut length)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let header_len = u64::from_le_bytes(length);
        if header_len > 100 * 1024 * 1024 {
            return Err("safetensors header is implausibly large".to_string());
        }
        let mut header = vec![0u8; header_len as usize];
        file.read_exact(&mut header)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let document = json::parse(&header).map_err(|error| error.to_string())?;
        let members = document
            .as_object()
            .ok_or("safetensors header is not an object")?;

        let mut entries = BTreeMap::new();
        for (name, value) in members {
            if name == "__metadata__" {
                continue;
            }
            let dtype = value
                .get("dtype")
                .and_then(json::Value::as_str)
                .ok_or_else(|| format!("{name}: no dtype"))?;
            if dtype != "F32" {
                return Err(format!(
                    "{name}: dtype {dtype} — re-export with fetch.py, which widens to F32"
                ));
            }
            let shape = value
                .get("shape")
                .and_then(json::Value::as_array)
                .ok_or_else(|| format!("{name}: no shape"))?
                .iter()
                .map(|extent| extent.as_usize().map(|value| value as u64))
                .collect::<Option<Vec<u64>>>()
                .ok_or_else(|| format!("{name}: bad shape"))?;
            let offsets = value
                .get("data_offsets")
                .and_then(json::Value::as_array)
                .ok_or_else(|| format!("{name}: no data_offsets"))?;
            let start = offsets
                .first()
                .and_then(json::Value::as_usize)
                .ok_or_else(|| format!("{name}: bad data_offsets"))? as u64;
            let end = offsets
                .get(1)
                .and_then(json::Value::as_usize)
                .ok_or_else(|| format!("{name}: bad data_offsets"))? as u64;
            let entry = Entry { shape, start, end };
            let expected = entry
                .elements()
                .checked_mul(4)
                .ok_or_else(|| format!("{name}: element count overflows"))?;
            if end.checked_sub(start) != Some(expected) {
                return Err(format!("{name}: extent disagrees with shape"));
            }
            entries.insert(name.clone(), entry);
        }

        Ok(Self {
            file,
            payload_base: 8 + header_len,
            entries,
        })
    }

    /// Every tensor name in the file.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// The entry for `name`.
    pub fn entry(&self, name: &str) -> Result<&Entry, String> {
        self.entries
            .get(name)
            .ok_or_else(|| format!("{name}: not in the checkpoint"))
    }

    /// Reads a tensor's values.
    pub fn read(&mut self, name: &str) -> Result<Vec<f32>, String> {
        let entry = self.entry(name)?.clone();
        let byte_len = (entry.end - entry.start) as usize;
        self.file
            .seek(SeekFrom::Start(self.payload_base + entry.start))
            .map_err(|error| format!("{name}: {error}"))?;
        let mut raw = vec![0u8; byte_len];
        self.file
            .read_exact(&mut raw)
            .map_err(|error| format!("{name}: {error}"))?;
        let mut values = Vec::with_capacity(byte_len / 4);
        for chunk in raw.chunks_exact(4) {
            values.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        Ok(values)
    }
}
