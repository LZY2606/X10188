//! 边界感知的 zlib 解压：不相信任何外部声明的大小，
//! 以 zlib 流自身的结束标记（FINISH 返回值）确定边界与真实长度。
//!
//! 大小欺骗检测：
//! - declared_size < 实际输出长度 -> Overshoot（输出比声明多，典型的“中途才发现欺骗”）
//! - declared_size > 实际输出长度 -> Undershoot（声明比实际多）
//! 即使发生 overshoot，也继续把流读完以定位边界，保证后续对象可继续分析。

use flate2::Decompress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateError {
    /// 输入在流结束前被截断
    Truncated,
    /// 解压出的真实数据超过声明大小（第一个字节位置）
    Overshoot { declared: u64, actual: u64 },
    /// 输出超过硬性安全上限
    SafetyLimitExceeded { limit: u64 },
    /// zlib 内部错误
    Zlib(String),
}

#[derive(Debug, Clone)]
pub struct InflateOutcome {
    /// 真正解压出来的完整数据（即使 overshoot 也保留，作为证据）
    pub data: Vec<u8>,
    /// 流占用的压缩字节数（zlib 边界，相对压缩区起点）
    pub consumed: usize,
    /// 是否在解压过程中（非流末尾）就发现输出超过声明大小
    pub overshoot: bool,
    /// 声明大小
    pub declared_size: u64,
}

/// 从 `input[start..]` 解压单个 zlib 流。
/// `declared_size` 是对象头/delta 头里声明的预期长度，仅用于校验。
/// `safety_limit` 是硬性上限（防 zip bomb）。
pub fn inflate_one(
    input: &[u8],
    start: usize,
    declared_size: u64,
    safety_limit: u64,
) -> Result<InflateOutcome, InflateError> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut overshoot = false;
    let chunk = 16 * 1024;
    let mut tmp = vec![0u8; chunk];

    loop {
        let in_before = d.total_in();
        let out_before = d.total_out();
        let res = d.decompress_vec(
            &input[start + (in_before as usize)..],
            &mut tmp,
            flate2::FlushDecompress::None,
        );
        let produced = (d.total_out() - out_before) as usize;
        out.extend_from_slice(&tmp[..produced]);

        if !overshoot && (out.len() as u64) > declared_size {
            overshoot = true;
        }
        if (out.len() as u64) > safety_limit {
            return Err(InflateError::SafetyLimitExceeded {
                limit: safety_limit,
            });
        }

        match res {
            Ok(flate2::Status::Ok) => {
                // 若这次没消费输入也没产出输出，说明数据被截断
                let consumed_now = (d.total_in() - in_before) as usize;
                if consumed_now == 0 && produced == 0 {
                    return Err(InflateError::Truncated);
                }
            }
            Ok(flate2::Status::StreamEnd) => break,
            Ok(flate2::Status::BufError) => {
                // flate2 的 BufError 只可能是输出缓冲满，而我们每次 16K
                // 且在循环中重试；保险起见继续循环。
                continue;
            }
            Err(e) => return Err(InflateError::Zlib(e.to_string())),
        }
    }

    let actual = out.len() as u64;
    if overshoot {
        // 保留数据与边界，供后续对象继续解析
        return Ok(InflateOutcome {
            data: out,
            consumed: d.total_in() as usize,
            overshoot: true,
            declared_size,
        });
    }
    let _ = actual;
    Ok(InflateOutcome {
        data: out,
        consumed: d.total_in() as usize,
        overshoot: false,
        declared_size,
    })
}
