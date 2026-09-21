//! 受限 zlib 解压。
//!
//! 关键取证需求：
//! * 报告 zlib 流的精确边界（压缩数据消费到了输入的哪个偏移）；
//! * 在输出超过 `hard_limit` 的“那一刻”停止，区分三种情况：
//!   - 声明大小欺骗（实际输出 > header 里声明的长度）；
//!   - 资源预算上限（输出 > 预算允许）；
//!   - 真正的 zlib / deflate 损坏、截断、adler32 不匹配。
//!
//! 直接使用 miniz_oxide 的底层 core 接口，自己管理输出缓冲区增长。

use miniz_oxide::inflate::core::{decompress, inflate_flags, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateError {
    /// deflate 数据损坏（非法比特/长度/距离等）。
    Corrupt(String),
    /// 输入在流结束前耗尽。
    Truncated,
    /// 解压完成但 adler32 校验失败。
    Adler32Mismatch,
    /// 输出超过调用方给定的硬上限。
    LimitExceeded { produced: usize, limit: usize },
}

/// 解压失败时仍然保留的“部分进度”，用于取证与借助 index 重新对齐扫描。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflateFailure {
    pub kind: InflateError,
    /// 失败前已消费的压缩字节数。
    pub consumed: usize,
    /// 失败前已产出的解压字节数。
    pub produced: usize,
}

#[derive(Debug)]
pub struct InflateOutcome {
    pub data: Vec<u8>,
    /// 从输入中实际消费的压缩字节数（zlib 流精确边界）。
    pub consumed: usize,
    /// 流结束后剩余未消费字节数（异常尾随数据时可用于取证）。
    pub trailing: usize,
}

/// 从 `input[0..]` 解压一条 zlib 流。
///
/// `hard_limit`：输出字节数的绝对上限；一旦即将写超过该值，立即返回
/// [`InflateError::LimitExceeded`]（部分输出不会作为完整对象返回）。
///
/// `expected_size`：可选的头声明大小。仅用于帮助预分配；真正的大小欺骗检测
/// 由调用方在得到最终输出长度后与声明值比较完成（我们不能信任“声明刚好等于上限”
/// 的情况，因此硬上限取二者较小值也会由调用方决定）。
pub fn inflate_zlib_bounded(
    input: &[u8],
    hard_limit: usize,
    expected_size: Option<usize>,
) -> Result<InflateOutcome, InflateFailure> {
    let flags = inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
        | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
        | inflate_flags::TINFL_FLAG_HAS_MORE_INPUT;

    let mut decomp = DecompressorOxide::default();

    let initial = expected_size
        .unwrap_or(0)
        .clamp(64, hard_limit.max(64))
        .min(hard_limit.max(64));
    let mut out: Vec<u8> = vec![0u8; initial.min(1 << 20).max(64)];
    let mut out_pos = 0usize;
    let mut in_pos = 0usize;

    let fail = |kind: InflateError| -> InflateFailure {
        InflateFailure {
            kind,
            consumed: in_pos,
            produced: out_pos,
        }
    };

    loop {
        let (status, in_consumed, out_written) =
            decompress(&mut decomp, &input[in_pos..], &mut out, out_pos, flags);
        in_pos += in_consumed;
        out_pos += out_written;

        match status {
            TINFLStatus::Done => {
                out.truncate(out_pos);
                return Ok(InflateOutcome {
                    data: out,
                    consumed: in_pos,
                    trailing: input.len() - in_pos,
                });
            }
            TINFLStatus::HasMoreOutput | TINFLStatus::NeedsMoreInput => {
                // 输出缓冲满了？
                if out_pos == out.len() {
                    if out_pos >= hard_limit {
                        return Err(fail(InflateError::LimitExceeded {
                            produced: out_pos,
                            limit: hard_limit,
                        }));
                    }
                    let new_len = (out.len().saturating_mul(2))
                        .min(hard_limit.saturating_add(1))
                        .max(out.len() + 1);
                    out.resize(new_len, 0);
                }
                if in_pos >= input.len() {
                    // miniz 在 HAS_MORE_INPUT 下会返回 NeedsMoreInput；这表示流被截断。
                    if status == TINFLStatus::NeedsMoreInput {
                        return Err(fail(InflateError::Truncated));
                    }
                    return Err(fail(InflateError::Truncated));
                }
            }
            TINFLStatus::Adler32Mismatch => return Err(fail(InflateError::Adler32Mismatch)),
            other => {
                return Err(fail(InflateError::Corrupt(format!("inflate status: {other:?}"))));
            }
        }
    }
}

/// 计算 zlib 流（含头与 adler32 尾）字节的 CRC32 —— Git index 校验的对象范围。
pub fn crc32_of(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::deflate::compress_to_vec_zlib;

    #[test]
    fn roundtrip_reports_exact_boundary() {
        let payload = b"hello zlib boundary".repeat(10);
        let z = compress_to_vec_zlib(&payload, 6);
        let mut padded = z.clone();
        padded.extend_from_slice(b"GARBAGE_TRAILER");
        let r = inflate_zlib_bounded(&padded, 1 << 20, Some(payload.len())).unwrap();
        assert_eq!(r.data, payload);
        assert_eq!(r.consumed, z.len());
        assert_eq!(r.trailing, b"GARBAGE_TRAILER".len());
    }

    #[test]
    fn limit_is_detected_midstream() {
        let payload = vec![0x55u8; 10_000];
        let z = compress_to_vec_zlib(&payload, 9);
        let err = inflate_zlib_bounded(&z, 100, None).unwrap_err();
        match err.kind {
            InflateError::LimitExceeded { produced, limit } => {
                assert_eq!(limit, 100);
                assert!(produced >= 100);
            }
            other => panic!("expected limit, got {other:?}"),
        }
    }

    #[test]
    fn truncated_stream_detected() {
        let payload = vec![0x33u8; 5000];
        let z = compress_to_vec_zlib(&payload, 6);
        let cut = &z[..z.len() - 3];
        assert!(matches!(
            inflate_zlib_bounded(cut, 1 << 20, None),
            Err(e) if matches!(
                e.kind,
                InflateError::Truncated | InflateError::Corrupt(_)
            )
        ));
    }
}
