//! Git delta application and per-step forensics.
//!
//! Delta wire format (zlib-decompressed already):
//!   base_size   = varint
//!   result_size = varint
//!   commands:
//!     op & 0x80        -> copy: one mask byte, up to 4 offset bytes then up to
//!                         3 size bytes (MSB first per byte, little-endian)
//!     op != 0          -> insert: next `op` literal bytes
//!     op == 0          -> reserved / invalid

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// One applied delta instruction with its raw byte range in the delta buffer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeltaInstr {
    pub kind: String, // "copy" | "insert"
    /// Half-open byte range `[start,end)` inside the *instruction region*
    /// (i.e. delta offsets excluding the two size varints).
    pub start: usize,
    pub end: usize,
    /// For copy: base offset; for insert: 0.
    pub src_offset: usize,
    /// Bytes read from base (copy) or literals appended (insert).
    pub length: usize,
    /// Output position this instruction wrote to.
    pub out_pos: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeltaStep {
    /// Offset in the delta where the base-size varint begins (always 0).
    pub delta_start: usize,
    pub base_size: usize,
    pub result_size: usize,
    /// Bytes consumed by the two size varints.
    pub header_len: usize,
    pub instructions: Vec<DeltaInstr>,
    /// Checks performed and their result.
    pub checks: Vec<(String, bool, String)>,
    pub output_len: usize,
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let mut shift = 0u32;
    let mut val = 0u64;
    loop {
        if *pos >= buf.len() {
            return Err(Error::Delta("unexpected end while reading size varint".into()));
        }
        let b = buf[*pos];
        *pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(val)
}

/// Apply `delta` to `base`, recording a forensic [`DeltaStep`].
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaStep)> {
    let mut step = DeltaStep { delta_start: 0, ..Default::default() };
    let mut pos = 0usize;
    let base_size = read_varint(delta, &mut pos)? as usize;
    let result_size = read_varint(delta, &mut pos)? as usize;
    let header_len = pos;
    step.base_size = base_size;
    step.result_size = result_size;
    step.header_len = header_len;

    let mut checks = Vec::new();
    checks.push((
        "base_size_matches".into(),
        base_size == base.len(),
        format!("delta declares base {base_size}, actual base {}", base.len()),
    ));
    if base_size != base.len() {
        return Err(Error::Delta(format!(
            "base size mismatch: delta wants {base_size}, got {}",
            base.len()
        )));
    }

    // Preallocate, but do not trust result_size unconditionally; insertion
    // commands are still range checked against the actual delta bytes.
    let cap = result_size.min(256 * 1024 * 1024);
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(16 * 1024 * 1024));

    while pos < delta.len() {
        let op = delta[pos];
        let instr_start = pos - header_len;
        if op & 0x80 != 0 {
            // COPY
            pos += 1;
            let mut cp_off: usize = 0;
            let mut cp_size: usize = 0;
            if op & 0x01 != 0 {
                cp_off |= take_byte(delta, &mut pos)? as usize;
            }
            if op & 0x02 != 0 {
                cp_off |= (take_byte(delta, &mut pos)? as usize) << 8;
            }
            if op & 0x04 != 0 {
                cp_off |= (take_byte(delta, &mut pos)? as usize) << 16;
            }
            if op & 0x08 != 0 {
                cp_off |= (take_byte(delta, &mut pos)? as usize) << 24;
            }
            if op & 0x10 != 0 {
                cp_size |= take_byte(delta, &mut pos)? as usize;
            }
            if op & 0x20 != 0 {
                cp_size |= (take_byte(delta, &mut pos)? as usize) << 8;
            }
            if op & 0x40 != 0 {
                cp_size |= (take_byte(delta, &mut pos)? as usize) << 16;
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off.checked_add(cp_size).ok_or_else(|| {
                Error::Delta("copy offset+size overflow".into())
            })?;
            if end > base.len() {
                return Err(Error::Delta(format!(
                    "copy out of bounds: base offset {cp_off} size {cp_size}, base len {}",
                    base.len()
                )));
            }
            let out_pos = out.len();
            out.extend_from_slice(&base[cp_off..end]);
            step.instructions.push(DeltaInstr {
                kind: "copy".into(),
                start: instr_start,
                end: pos - header_len,
                src_offset: cp_off,
                length: cp_size,
                out_pos,
            });
        } else if op != 0 {
            // INSERT
            let n = op as usize;
            pos += 1;
            if pos + n > delta.len() {
                return Err(Error::Delta("insert overruns delta buffer".into()));
            }
            let out_pos = out.len();
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
            step.instructions.push(DeltaInstr {
                kind: "insert".into(),
                start: instr_start,
                end: pos - header_len,
                src_offset: 0,
                length: n,
                out_pos,
            });
        } else {
            return Err(Error::Delta("reserved zero opcode encountered".into()));
        }
    }

    let out_ok = out.len() == result_size;
    checks.push((
        "result_size_matches".into(),
        out_ok,
        format!("delta declares result {result_size}, produced {}", out.len()),
    ));
    if !out_ok {
        return Err(Error::Delta(format!(
            "result size mismatch: delta wants {result_size}, produced {}",
            out.len()
        )));
    }

    step.output_len = out.len();
    step.checks = checks;
    Ok((out, step))
}

fn take_byte(buf: &[u8], pos: &mut usize) -> Result<u8> {
    if *pos >= buf.len() {
        return Err(Error::Delta("copy command truncated".into()));
    }
    let b = buf[*pos];
    *pos += 1;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_copy() {
        let base = b"hello world";
        // result = "HELLO!!" + copy("world")  => build manually
        let mut d = Vec::new();
        put_var(&mut d, base.len() as u64);
        let result = b"!! world";
        put_var(&mut d, result.len() as u64);
        // copy base[6..11] = "world"
        d.push(0x80 | 0x10 | 0x01); // offset byte + size byte present
        d.push(6);
        d.push(5);
        // insert "!! "
        d.push(3);
        d.extend_from_slice(b"!! ");
        // copy base[6..11] again
        d.push(0x80 | 0x10 | 0x01);
        d.push(6);
        d.push(5);
        // That yields "world!! world" (13); adjust result expectation:
        let _ = result;
        let (out, step) = apply_delta(base, &d).unwrap();
        assert_eq!(out, b"world!! world");
        assert_eq!(step.instructions.len(), 3);
        assert!(step.checks.iter().all(|c| c.1));
    }

    fn put_var(d: &mut Vec<u8>, mut v: u64) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            d.push(b);
            if v == 0 {
                break;
            }
        }
    }

    #[test]
    fn base_size_lie_errors() {
        let mut d = Vec::new();
        put_var(&mut d, 99); // wrong base size
        put_var(&mut d, 0);
        assert!(apply_delta(b"abc", &d).is_err());
    }
}
