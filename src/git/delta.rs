//! Git delta 指令解析与应用，记录每条指令的原始字节范围。

use crate::git::reader::Reader;
use std::io;

#[derive(Debug, Clone)]
pub enum DeltaOp {
    /// 直接插入新数据，data_off 指向指令流内的数据。
    Insert {
        op_off: usize,
        data_off: usize,
        len: usize,
    },
    /// 从 base 拷贝。
    Copy {
        op_off: usize,
        op_len: usize,
        src_off: usize,
        len: usize,
    },
}

#[derive(Debug, Clone)]
pub struct ParsedDelta {
    pub base_size: u64,
    pub result_size: u64,
    pub ops: Vec<DeltaOp>,
    pub data_end: usize,
}

impl ParsedDelta {
    /// 指令覆盖的原始字节范围（含内联数据）。
    pub fn instruction_range(&self) -> (usize, usize) {
        match self.ops.first() {
            Some(first) => {
                let start = match first {
                    DeltaOp::Insert { op_off, .. } | DeltaOp::Copy { op_off, .. } => *op_off,
                };
                (start, self.data_end)
            }
            None => (self.data_end, self.data_end),
        }
    }
}

pub fn parse(data: &[u8]) -> io::Result<ParsedDelta> {
    let mut r = Reader::new(data);
    let base_size = r.size_encoding()?;
    let result_size = r.size_encoding()?;
    let mut ops = Vec::new();
    loop {
        if r.remaining() == 0 {
            break;
        }
        let op_off = r.pos;
        let op = r.u8()?;
        if op == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid delta opcode 0 at {}", op_off),
            ));
        }
        if op & 0x80 != 0 {
            // copy
            let mut so: u32 = 0;
            let mut sl: u32 = 0;
            for (i, shift) in [0u32, 8, 16, 24].iter().enumerate() {
                if op & (1 << i) != 0 {
                    so |= u32::from(r.u8()?) << shift;
                }
            }
            for (i, shift) in [0u32, 8, 16].iter().enumerate() {
                if op & (1 << (4 + i)) != 0 {
                    sl |= u32::from(r.u8()?) << shift;
                }
            }
            if sl == 0 {
                sl = 0x10000;
            }
            ops.push(DeltaOp::Copy {
                op_off,
                op_len: r.pos - op_off,
                src_off: so as usize,
                len: sl as usize,
            });
        } else {
            let len = op as usize;
            let data_off = r.pos;
            r.take(len)?;
            ops.push(DeltaOp::Insert {
                op_off,
                data_off,
                len,
            });
        }
    }
    Ok(ParsedDelta {
        base_size,
        result_size,
        ops,
        data_end: r.pos,
    })
}

/// 应用 delta。返回 Err 表示指令越界 / 长度欺骗等，不能产出任何对象。
pub fn apply(base: &[u8], delta: &ParsedDelta, raw: &[u8]) -> io::Result<Vec<u8>> {
    if base.len() as u64 != delta.base_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "delta base size spoofed: header says {}, actual {}",
                delta.base_size,
                base.len()
            ),
        ));
    }
    let mut out = Vec::with_capacity(delta.result_size.min(1 << 28) as usize);
    for op in &delta.ops {
        match op {
            DeltaOp::Insert {
                data_off, len, ..
            } => {
                let piece = raw
                    .get(*data_off..data_off + len)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "insert range oob"))?;
                out.extend_from_slice(piece);
            }
            DeltaOp::Copy {
                src_off, len, ..
            } => {
                let end = src_off
                    .checked_add(*len)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "copy offset overflow"))?;
                if end > base.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "copy out of base: off={} len={} base_len={}",
                            src_off, len, base.len()
                        ),
                    ));
                }
                out.extend_from_slice(&base[*src_off..end]);
            }
        }
    }
    if out.len() as u64 != delta.result_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "delta result size spoofed: header says {}, produced {}",
                delta.result_size,
                out.len()
            ),
        ));
    }
    Ok(out)
}
