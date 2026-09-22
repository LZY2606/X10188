use crate::gitbase::read_delta_varint;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DeltaOp {
    pub kind: String,
    pub delta_offset: usize,
    pub length: usize,
    /// insert: offset inside the delta blob of the inserted bytes
    pub insert_src_offset: Option<usize>,
    /// copy: range inside the base object
    pub base_offset: Option<usize>,
    pub out_before: usize,
    pub out_after: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaTrace {
    pub base_size: u64,
    pub result_size: u64,
    pub header_len: usize,
    pub ops: Vec<DeltaOp>,
}

fn read_copy_params(buf: &[u8], pos: &mut usize, flags: u8) -> Option<(usize, usize)> {
    let mut offset: usize = 0;
    let mut size: usize = 0;
    for i in 0..4u32 {
        if flags & (1 << i) != 0 {
            if *pos >= buf.len() {
                return None;
            }
            offset |= (buf[*pos] as usize) << (8 * i);
            *pos += 1;
        }
    }
    for i in 0..3u32 {
        if flags & (1 << (4 + i)) != 0 {
            if *pos >= buf.len() {
                return None;
            }
            size |= (buf[*pos] as usize) << (8 * i);
            *pos += 1;
        }
    }
    if size == 0 {
        size = 0x10000;
    }
    Some((offset, size))
}

/// Apply a git delta against `base`, recording every instruction.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaTrace), String> {
    let mut pos = 0usize;
    let base_size = read_delta_varint(delta, &mut pos).ok_or("delta: truncated base size")?;
    let result_size =
        read_delta_varint(delta, &mut pos).ok_or("delta: truncated result size")?;
    if base_size as usize != base.len() {
        return Err(format!(
            "delta: base size mismatch (header {base_size}, actual {})",
            base.len()
        ));
    }
    let header_len = pos;
    let mut ops = Vec::new();
    let mut out: Vec<u8> = Vec::with_capacity(result_size.min(1 << 28) as usize);

    while pos < delta.len() {
        let out_before = out.len();
        let op_byte_pos = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            let (offset, size) =
                read_copy_params(delta, &mut pos, op).ok_or("delta: bad copy params")?;
            if offset.checked_add(size).map_or(true, |end| end > base.len()) {
                return Err(format!(
                    "delta: copy out of base range (offset {offset}, size {size}, base {})",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[offset..offset + size]);
            ops.push(DeltaOp {
                kind: "copy".into(),
                delta_offset: op_byte_pos,
                length: size,
                insert_src_offset: None,
                base_offset: Some(offset),
                out_before,
                out_after: out.len(),
            });
        } else if op != 0 {
            let size = op as usize;
            if pos + size > delta.len() {
                return Err("delta: truncated insert".into());
            }
            out.extend_from_slice(&delta[pos..pos + size]);
            ops.push(DeltaOp {
                kind: "insert".into(),
                delta_offset: op_byte_pos,
                length: size,
                insert_src_offset: Some(pos),
                base_offset: None,
                out_before,
                out_after: out.len(),
            });
            pos += size;
        } else {
            return Err("delta: reserved zero opcode".into());
        }
    }

    if out.len() as u64 != result_size {
        return Err(format!(
            "delta: result size mismatch (header {result_size}, produced {})",
            out.len()
        ));
    }
    Ok((
        out,
        DeltaTrace {
            base_size,
            result_size,
            header_len,
            ops,
        },
    ))
}
