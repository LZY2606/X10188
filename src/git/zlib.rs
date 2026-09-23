use flate2::{Decompress, FlushDecompress};

use super::types::InflateStatus;

/// 硬性解压器上限：无论声明大小如何，单条 zlib 流最多展开到这里，
/// 防止“大小欺骗”导致无界内存消耗。
pub const HARD_OUTPUT_LIMIT: usize = 256 * 1024 * 1024;

pub struct InflateResult {
    pub status: InflateStatus,
    /// 实际输出（若 SizeSpoof/Truncated，为解压到一半的部分数据）。
    pub data: Vec<u8>,
    /// 消耗的输入字节数（zlib 流在 pack 中的边界）。
    pub input_consumed: usize,
}

/// 从 `input[pos..]` 处解压一条 zlib 流。
///
/// `declared_size` 是 entry header 里声明的展开长度（Git 本身用它分配
/// 缓冲区），因此任何“声明 10 字节、实际吐出 1GB”的条目在展开过程中
/// 即可判定为 `SizeSpoof`，不必等到整条流解压完。
pub fn inflate_entry(input: &[u8], pos: usize, declared_size: u64) -> InflateResult {
    let mut z = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut status = InflateStatus::Ok;

    // 允许比声明值略大的判定窗口在循环中处理，这里先按声明值预留。
    let cap = declared_size.min(HARD_OUTPUT_LIMIT as u64) as usize;
    out.reserve(cap.min(1024 * 1024));

    let mut last_in = 0usize;
    let mut last_out = 0usize;
    loop {
        let before_in = z.total_in() as usize;
        let before_out = z.total_out() as usize;
        let remaining_in = if pos + before_in >= input.len() {
            &[][..]
        } else {
            &input[pos + before_in..]
        };
        let out_pos = out.len();
        let step = 4096usize;
        out.resize(out_pos + step, 0u8);
        let before = z.total_in();
        let res = z.decompress(remaining_in, &mut out[out_pos..], FlushDecompress::None);
        let got_in = (z.total_in() - before) as usize;
        let got_out = z.total_out() as usize - out_pos;
        out.truncate(out_pos + got_out);

        match res {
            Ok(flate2::Status::Ok) => {}
            Ok(flate2::Status::StreamEnd) => {
                status = InflateStatus::Ok;
                break;
            }
            Ok(flate2::Status::BufError) => {
                // 输入与输出都无进展才需要避免死循环。
                if got_in == 0 && got_out == 0 {
                    status = InflateStatus::Truncated;
                    break;
                }
            }
            Err(_) => {
                status = InflateStatus::ZlibError;
                break;
            }
        }

        // 大小欺骗：实际展开长度超过声明大小（声明为 Git 头中的可信预算）。
        if out.len() as u64 > declared_size {
            status = InflateStatus::SizeSpoof;
            break;
        }
        if out.len() > HARD_OUTPUT_LIMIT {
            status = InflateStatus::SizeSpoof;
            break;
        }

        last_in = before_in + got_in;
        last_out = before_out + got_out;
        let _ = (last_in, last_out);
        // 输入耗尽但流未结束。
        if pos + z.total_in() as usize >= input.len() && got_out == 0 {
            // 再尝试一次空输入以确认。
            if got_in == 0 {
                status = InflateStatus::Truncated;
                break;
            }
        }
    }

    InflateResult {
        status,
        data: out,
        input_consumed: z.total_in() as usize,
    }
}

/// 解压 loose object（zlib(deflate(header NUL payload))），不预先信任长度。
pub fn inflate_loose(input: &[u8]) -> InflateResult {
    let mut z = Decompress::new(true);
    let mut out: Vec<u8>::with_capacity(4096);
    let mut status = InflateStatus::Ok;
    loop {
        let before_in = z.total_in() as usize;
        let remaining_in = if before_in >= input.len() {
            &[][..]
        } else {
            &input[before_in..]
        };
        let out_pos = out.len();
        out.resize(out_pos + 4096, 0u8);
        let before = z.total_in();
        let res = z.decompress(remaining_in, &mut out[out_pos..], FlushDecompress::None);
        let got_in = (z.total_in() - before) as usize;
        let got_out = z.total_out() as usize - out_pos;
        out.truncate(out_pos + got_out);
        match res {
            Ok(flate2::Status::Ok) => {}
            Ok(flate2::Status::StreamEnd) => break,
            Ok(flate2::Status::BufError) => {
                if got_in == 0 && got_out == 0 {
                    status = InflateStatus::Truncated;
                    break;
                }
            }
            Err(_) => {
                status = InflateStatus::ZlibError;
                break;
            }
        }
        if out.len() > HARD_OUTPUT_LIMIT {
            status = InflateStatus::SizeSpoof;
            break;
        }
        if before_in + got_in >= input.len() && got_out == 0 {
            status = InflateStatus::Truncated;
            break;
        }
    }
    InflateResult { status, data: out, input_consumed: z.total_in() as usize }
}

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

/// 构建测试 pack 时使用的 zlib 压缩器。
pub fn deflate_raw(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
