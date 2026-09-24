//! zlib 流边界探测与带预算的解压。
//!
//! 核心解析不依赖系统 git。使用纯 Rust flate2，逐块解压，
//! 既统计精确的输入消费字节（zlib 流边界 / CRC 范围），
//! 又以解压字节数为硬预算，在“解压到一半才发现大小欺骗”时
//! 给出明确错误，而不是把部分输出当完整对象。

use std::io::Read;

/// 解压结果：解压数据 + 在输入中消费的字节数（zlib 流边界）。
pub struct Inflated {
    pub data: Vec<u8>,
    pub consumed: usize,
}

struct CountingReader<'a> {
    inner: &'a [u8],
    read: usize,
}

impl<'a> Read for CountingReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n;
        Ok(n)
    }
}

/// 从 `input[start..]` 解压一条 zlib 流。
///
/// `max_output` 是硬上限：解压字节数一旦超过立即报错，
/// 用于阻止压缩炸弹 / 伪造极小 size 的 delta 或对象。
pub fn inflate_slice(input: &[u8], start: usize, max_output: usize) -> Result<Inflated, String> {
    if start >= input.len() {
        return Err("zlib 起始偏移越界".to_string());
    }
    let counting = CountingReader {
        inner: &input[start..],
        read: 0,
    };
    let mut dec = flate2::read::ZlibDecoder::new(counting);
    let mut data = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match dec.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if data.len() + n > max_output {
                    return Err(format!(
                        "解压超过预算上限 {max_output} 字节（大小欺骗 / 压缩炸弹）"
                    ));
                }
                data.extend_from_slice(&chunk[..n]);
            }
            Err(e) => {
                return Err(format!(
                    "zlib 流损坏（已解压 {} 字节后失败）: {e}",
                    data.len()
                ));
            }
        }
    }
    let consumed = dec.into_inner().read;
    if consumed == 0 {
        return Err("zlib 流为空".to_string());
    }
    Ok(Inflated { data, consumed })
}

/// 直接对整段切片做一次 zlib 压缩（测试与 loose 写入用）。
pub fn deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("zlib 压缩");
    enc.finish().expect("zlib finish")
}
