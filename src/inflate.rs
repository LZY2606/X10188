use std::fmt;

use flate2::{Decompress, FlushDecompress, Status};

pub const HARD_CAP: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateIssue {
    Truncated,
    Corrupt(String),
    SizeSpoof { declared: u64, produced: u64 },
    SizeMismatch { declared: u64, actual: u64 },
    OverHardCap { declared: u64 },
}

impl fmt::Display for InflateIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InflateIssue::Truncated => write!(f, "zlib 流被截断"),
            InflateIssue::Corrupt(m) => write!(f, "zlib 流损坏: {m}"),
            InflateIssue::SizeSpoof { declared, produced } => write!(
                f,
                "大小欺骗: 声明 {declared} 字节, 实际解压已超过 {produced} 字节"
            ),
            InflateIssue::SizeMismatch { declared, actual } => {
                write!(f, "大小不符: 声明 {declared} 字节, 实际解压 {actual} 字节")
            }
            InflateIssue::OverHardCap { declared } => {
                write!(f, "声明大小 {declared} 超过硬性安全上限")
            }
        }
    }
}

pub fn inflate_bounded(input: &[u8], limit: u64) -> Result<(Vec<u8>, usize), InflateIssue> {
    let mut de = Decompress::new(true);
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    let mut in_off = 0usize;
    loop {
        let before_in = de.total_in();
        let before_out = de.total_out();
        let status = de
            .decompress(&input[in_off..], &mut buf, FlushDecompress::None)
            .map_err(|e| InflateIssue::Corrupt(e.to_string()))?;
        let consumed = (de.total_in() - before_in) as usize;
        let produced = (de.total_out() - before_out) as usize;
        in_off += consumed;
        out.extend_from_slice(&buf[..produced]);
        if out.len() as u64 > limit {
            return Err(InflateIssue::SizeSpoof {
                declared: limit,
                produced: out.len() as u64,
            });
        }
        match status {
            Status::StreamEnd => return Ok((out, in_off)),
            Status::Ok => {
                if consumed == 0 && produced == 0 {
                    if in_off >= input.len() {
                        return Err(InflateIssue::Truncated);
                    }
                    return Err(InflateIssue::Corrupt("解压器停滞".into()));
                }
            }
            Status::BufError => {
                if in_off >= input.len() {
                    return Err(InflateIssue::Truncated);
                }
                return Err(InflateIssue::Corrupt("解压器缓冲区错误".into()));
            }
        }
    }
}

pub fn inflate_entry(input: &[u8], declared: u64) -> Result<(Vec<u8>, usize), InflateIssue> {
    let cap = declared.min(HARD_CAP);
    match inflate_bounded(input, cap) {
        Ok((out, used)) => {
            if out.len() as u64 != declared {
                return Err(InflateIssue::SizeMismatch {
                    declared,
                    actual: out.len() as u64,
                });
            }
            Ok((out, used))
        }
        Err(InflateIssue::SizeSpoof { produced, .. }) if declared > HARD_CAP => {
            let _ = produced;
            Err(InflateIssue::OverHardCap { declared })
        }
        Err(InflateIssue::SizeSpoof { produced, .. }) => Err(InflateIssue::SizeSpoof {
            declared,
            produced,
        }),
        Err(e) => Err(e),
    }
}

pub fn inflate_exact(input: &[u8], limit: u64) -> Result<Vec<u8>, InflateIssue> {
    let (out, used) = inflate_bounded(input, limit)?;
    if used != input.len() {
        return Err(InflateIssue::Corrupt(format!(
            "流结束后仍有 {} 字节尾随数据",
            input.len() - used
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zlib(data: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn roundtrip_and_boundary() {
        let payload = b"some pack object payload".repeat(10);
        let mut stream = zlib(&payload);
        let clen = stream.len();
        stream.extend_from_slice(b"NEXT-ENTRY");
        let (out, used) = inflate_bounded(&stream, 1 << 20).unwrap();
        assert_eq!(out, payload);
        assert_eq!(used, clen);
    }

    #[test]
    fn spoof_detected() {
        let payload = vec![7u8; 1000];
        let stream = zlib(&payload);
        let err = inflate_bounded(&stream, 100).unwrap_err();
        assert!(matches!(err, InflateIssue::SizeSpoof { .. }));
    }

    #[test]
    fn truncated_detected() {
        let payload = vec![3u8; 500];
        let stream = zlib(&payload);
        let cut = &stream[..stream.len() / 2];
        let err = inflate_bounded(cut, 1 << 20).unwrap_err();
        assert!(matches!(err, InflateIssue::Truncated | InflateIssue::Corrupt(_)));
    }
}
