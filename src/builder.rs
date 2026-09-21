use crate::git::{deflate_zlib, git_object_id, object_header, ObjectType};
use sha1::{Digest, Sha1};

#[derive(Clone)]
enum RawEntry {
    Base { kind: ObjectType, plain: Vec<u8>, oid: [u8; 20] },
    OfsDelta { base_index: usize, delta: Vec<u8> },
    RefDelta { base_oid: [u8; 20], delta: Vec<u8> },
}

pub struct PackBuilder {
    entries: Vec<RawEntry>,
}

impl Default for PackBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PackBuilder {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn add_base_object(&mut self, kind: ObjectType, content: &[u8]) -> usize {
        let plain = object_header(kind.name(), content);
        let oid = git_object_id(kind.name(), content);
        self.entries.push(RawEntry::Base { kind, plain, oid });
        self.entries.len() - 1
    }

    pub fn add_ofs_delta(&mut self, base_index: usize, delta: &[u8]) -> usize {
        self.entries.push(RawEntry::OfsDelta {
            base_index,
            delta: delta.to_vec(),
        });
        self.entries.len() - 1
    }

    pub fn add_ref_delta(&mut self, base_oid: [u8; 20], delta: &[u8]) -> usize {
        self.entries.push(RawEntry::RefDelta {
            base_oid,
            delta: delta.to_vec(),
        });
        self.entries.len() - 1
    }

    pub fn build(self) -> Vec<u8> {
        let encoded = self.encode_entries();
        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        for (_, bytes) in encoded {
            out.extend_from_slice(&bytes);
        }
        let mut hasher = Sha1::new();
        hasher.update(&out);
        out.extend_from_slice(&hasher.finalize());
        out
    }

    pub fn entry_offsets(&self) -> Vec<usize> {
        let encoded = self.encode_entries();
        let mut offset = 12usize;
        let mut offsets = Vec::new();
        for (start, bytes) in encoded {
            offsets.push(start);
            offset += bytes.len();
        }
        let _ = offset;
        offsets
    }

    fn encode_entries(&self) -> Vec<(usize, Vec<u8>)> {
        let mut encoded: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut offset = 12usize;
        for entry in &self.entries {
            let start = offset;
            let (kind, plain, base_index, base_oid) = match entry {
                RawEntry::Base { kind, plain, .. } => (*kind, plain, None, None),
                RawEntry::OfsDelta { base_index, delta } => {
                    (ObjectType::OfsDelta, delta, Some(*base_index), None)
                }
                RawEntry::RefDelta { base_oid, delta } => {
                    (ObjectType::RefDelta, delta, None, Some(*base_oid))
                }
            };
            let payload = deflate_zlib(plain);
            let mut bytes = Vec::new();
            let mut size = plain.len();
            let mut first = (kind.pack_code().unwrap() << 4) | ((size & 0x0f) as u8);
            size >>= 4;
            if size > 0 {
                first |= 0x80;
            }
            bytes.push(first);
            while size > 0 {
                let mut byte = (size & 0x7f) as u8;
                size >>= 7;
                if size > 0 {
                    byte |= 0x80;
                }
                bytes.push(byte);
            }
            if let Some(index) = base_index {
                let distance = start - encoded[index].0;
                let mut value = distance;
                let mut tail = vec![(value & 0x7f) as u8];
                value >>= 7;
                while value > 0 {
                    tail.push((0x80 | (value & 0x7f)) as u8);
                    value >>= 7;
                }
                tail.reverse();
                bytes.extend(tail);
            }
            if let Some(oid) = base_oid {
                bytes.extend_from_slice(&oid);
            }
            bytes.extend_from_slice(&payload);
            offset += bytes.len();
            encoded.push((start, bytes));
        }
        encoded
    }
}

pub fn write_delta(instructions: &[u8], source_len: usize, target_len: usize) -> Vec<u8> {
    let mut delta = encode_varint(source_len);
    delta.extend(encode_varint(target_len));
    delta.extend_from_slice(instructions);
    delta
}

pub fn encode_varint(mut value: usize) -> Vec<u8> {
    let mut out = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value > 0 {
        out.push((0x80 | (value & 0x7f)) as u8);
        value >>= 7;
    }
    out.reverse();
    out
}

pub fn insert_instruction(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 127);
    let mut out = vec![data.len() as u8];
    out.extend_from_slice(data);
    out
}

pub fn copy_instruction(offset: usize, size: usize) -> Vec<u8> {
    let mut opcode = 0x80u8;
    let mut body = Vec::new();
    for shift in (0..32).step_by(8) {
        let byte = ((offset >> shift) & 0xff) as u8;
        if byte != 0 {
            opcode |= 1 << (shift / 8);
            body.push(byte);
        }
    }
    for shift in (0..24).step_by(8) {
        let byte = ((size >> shift) & 0xff) as u8;
        if byte != 0 {
            opcode |= 1 << (4 + shift / 8);
            body.push(byte);
        }
    }
    let mut out = vec![opcode];
    out.extend(body);
    out
}
