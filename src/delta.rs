/// Git delta program parsing & application, with forensic reporting.

#[derive(Debug, Clone)]
pub enum Instr {
    Copy { src_off: u64, len: u64 },
    Insert { len: u64 },
}

#[derive(Debug, Clone)]
pub struct DeltaReport {
    pub src_size_declared: u64,
    pub tgt_size_declared: u64,
    /// Bytes consumed by the two size varints (header of the program).
    pub header_bytes: usize,
    /// Byte range of the instruction stream inside the program.
    pub instr_start: usize,
    pub instr_end: usize,
    pub instr_count: usize,
    pub copy_count: usize,
    pub insert_count: usize,
    pub input_len: usize,
    pub output_len: usize,
    pub ok: bool,
    pub error: Option<String>,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        let c = *data
            .get(*pos)
            .ok_or_else(|| "delta 尺寸 varint 越界".to_string())?;
        *pos += 1;
        v |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if c & 0x80 == 0 {
            return Ok(v);
        }
        if shift > 63 {
            return Err("delta 尺寸 varint 过长".into());
        }
    }
}

/// Apply delta `program` on top of `base`, returning the result plus a report.
pub fn apply_delta(base: &[u8], program: &[u8]) -> (Option<Vec<u8>>, DeltaReport) {
    let mut pos = 0usize;
    let mut report = |src, tgt, hdr, err: Option<String>| DeltaReport {
        src_size_declared: src,
        tgt_size_declared: tgt,
        header_bytes: hdr,
        instr_start: hdr,
        instr_end: program.len(),
        instr_count: 0,
        copy_count: 0,
        insert_count: 0,
        input_len: base.len(),
        output_len: 0,
        ok: false,
        error: err,
    };

    let src_size = match read_varint(program, &mut pos) {
        Ok(v) => v,
        Err(e) => return (None, report(0, 0, pos, Some(e))),
    };
    let tgt_size = match read_varint(program, &mut pos) {
        Ok(v) => v,
        Err(e) => return (None, report(src_size, 0, pos, Some(e))),
    };
    let header_bytes = pos;
    if src_size != base.len() as u64 {
        return (
            None,
            report(
                src_size,
                tgt_size,
                header_bytes,
                Some(format!(
                    "delta 源大小不匹配: 程序声明 {} 字节, base 实际 {} 字节",
                    src_size,
                    base.len()
                )),
            ),
        );
    }

    let mut out: Vec<u8> = Vec::with_capacity(tgt_size as usize);
    let mut instr_count = 0usize;
    let mut copy_count = 0usize;
    let mut insert_count = 0usize;

    while pos < program.len() {
        let op = program[pos];
        pos += 1;
        instr_count += 1;
        if op & 0x80 != 0 {
            // copy from base
            let mut src_off: u64 = 0;
            let mut len: u64 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    let b = match program.get(pos) {
                        Some(b) => *b,
                        None => {
                            return (
                                None,
                                fail(report(src_size, tgt_size, header_bytes, None), instr_count, copy_count, insert_count, &out, "copy 指令偏移字节越界"),
                            )
                        }
                    };
                    pos += 1;
                    src_off |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3 {
                if op & (0x10 << i) != 0 {
                    let b = match program.get(pos) {
                        Some(b) => *b,
                        None => {
                            return (
                                None,
                                fail(report(src_size, tgt_size, header_bytes, None), instr_count, copy_count, insert_count, &out, "copy 指令长度字节越界"),
                            )
                        }
                    };
                    pos += 1;
                    len |= (b as u64) << (8 * i);
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            let end = match src_off.checked_add(len) {
                Some(e) => e,
                None => {
                    return (
                        None,
                        fail(report(src_size, tgt_size, header_bytes, None), instr_count, copy_count, insert_count, &out, "copy 指令地址溢出"),
                    )
                }
            };
            if end > base.len() as u64 {
                return (
                    None,
                    fail(report(src_size, tgt_size, header_bytes, None), instr_count, copy_count, insert_count, &out,
                         &format!("copy 指令越界: [{}..{}] 超出 base 长度 {}", src_off, end, base.len())),
                );
            }
            out.extend_from_slice(&base[src_off as usize..end as usize]);
            copy_count += 1;
        } else if op != 0 {
            let len = op as usize;
            if pos + len > program.len() {
                return (
                    None,
                    fail(report(src_size, tgt_size, header_bytes, None), instr_count, copy_count, insert_count, &out,
                         "insert 指令数据越界"),
                );
            }
            out.extend_from_slice(&program[pos..pos + len]);
            pos += len;
            insert_count += 1;
        } else {
            return (
                None,
                fail(report(src_size, tgt_size, header_bytes, None), instr_count, copy_count, insert_count, &out,
                     "非法的 0 操作码"),
            );
        }
        if out.len() as u64 > tgt_size {
            return (
                None,
                fail(report(src_size, tgt_size, header_bytes, None), instr_count, copy_count, insert_count, &out,
                     &format!("输出超过声明目标大小 {} 字节 (大小欺骗)", tgt_size)),
            );
        }
    }

    let mut r = report(src_size, tgt_size, header_bytes, None);
    r.instr_count = instr_count;
    r.copy_count = copy_count;
    r.insert_count = insert_count;
    r.output_len = out.len();
    if out.len() as u64 != tgt_size {
        r.error = Some(format!(
            "输出大小欺骗: 声明 {} 字节, 实际产出 {} 字节",
            tgt_size,
            out.len()
        ));
        return (None, r);
    }
    r.ok = true;
    (Some(out), r)
}

fn fail(
    mut r: DeltaReport,
    instr_count: usize,
    copy_count: usize,
    insert_count: usize,
    out: &[u8],
    msg: &str,
) -> DeltaReport {
    r.instr_count = instr_count;
    r.copy_count = copy_count;
    r.insert_count = insert_count;
    r.output_len = out.len();
    r.error = Some(msg.to_string());
    r
}
