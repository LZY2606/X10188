//! zlib 流边界感知解压：基于 flate2 的 raw deflate，自己处理 2 字节
//! zlib 头与 4 字节 adler32 尾，精确报告压缩流占用的字节范围。
//! 这样可以定位“解压到一半才发现问题”的偏移证据。

use flate2::Decompress;
use flate2::FlushDecompress;

use super::{Error, Result};

/// Adler-32 滚动校验（RFC 1950）。
#[derive(Clone, Copy)]
pub struct Adler32 {
    s1: u32,
    s2: u32,
}

impl Adler32 {
    pub fn new() -> Self {
        Adler32 { s1: 1, s2: 0 }
    }
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.s1 = (self.s1 + b as u32) % 65521;
            self.s2 = (self.s2 + self.s1) % 65521;
        }
    }
    pub fn value(&self) -> u32 {
        (self.s2 << 16) | self.s1
    }
    pub fn checksum(data: &[u8]) -> u32 {
        let mut a = Adler32::new();
        a.update(data);
        a.value()
    }
}

pub struct InflateOutcome {
    /// 完整 zlib 流（头 + deflate + adler32 尾）占用的字节数。
    pub consumed: usize,
    /// deflate 体（不含 2 字节头）占用的字节数。
    pub deflate_len: usize,
    pub data: Vec<u8>,
    pub declared: Option<u64>,
}

/// 解压一个以 zlib 流开头的缓冲区。
/// * `max_size`: 输出字节硬上限，超过即报 SizeLie。
/// * `declared`: 调用方在对象头中声明的解压后大小；结尾用于发现大小欺骗。
pub fn inflate_zlib(
    input: &[u8],
    max_size: usize,
    declared: Option<u64>,
) -> Result<InflateOutcome> {
    if input.len() < 2 {
        return Err(Error::Zlib("zlib 头不足 2 字节".into()));
    }
    let cmf = input[0];
    let flg = input[1];
    if cmf & 0x0f != 8 {
        return Err(Error::Zlib(format!("不支持的压缩方法 {}", cmf & 0x0f)));
    }
    if (cmf as u16 * 256 + flg as u16) % 31 != 0 {
        return Err(Error::Zlib("zlib 头 FCHECK 不通过".into()));
    }
    if flg & 0x20 != 0 {
        return Err(Error::Zlib("不支持带预置字典的 zlib 流".into()));
    }

    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = 2usize;
    let mut finished = false;
    let mut adler = Adler32::new();

    // 逐字节喂入，精确锁定流结束位置；每次尽可能多地取回输出。
    while !finished {
        if in_pos >= input.len() {
            return Err(Error::Zlib(
                "压缩流在未结束时被截断（解压到一半发现数据不足）".into(),
            ));
        }
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let start = in_pos;
        let avail = &input[start..start + 1];
        let before_len = out.len();
        out.resize(before_len + 4096, 0);
        let result = dec.decompress(avail, &mut out[before_len..], FlushDecompress::None);
        let produced = (dec.total_out() - before_out) as usize;
        out.truncate(before_len + produced);
        let consumed_byte = (dec.total_in() - before_in) as usize;
        in_pos += consumed_byte;
        adler.update(&out[before_len..before_len + produced]);
        match result {
            Ok(FlushDecompress::StreamEnd) => finished = true,
            Ok(FlushDecompress::Ok | FlushDecompress::BufOut) => {}
            Err(e) => {
                return Err(Error::Zlib(format!(
                    "deflate 解码失败（消耗输入至偏移 {}）: {}",
                    in_pos, e
                )));
            }
        }
        if out.len() > max_size {
            return Err(Error::SizeLie(format!(
                "解压输出超过硬上限 {} 字节（在偏移 {} 处发现）",
                max_size, in_pos
            )));
        }
    }

    // 流结束，读取 4 字节 adler32（大端）。
    if in_pos + 4 > input.len() {
        return Err(Error::Zlib("zlib adler32 尾被截断".into()));
    }
    let stored =
        u32::from_be_bytes([input[in_pos], input[in_pos + 1], input[in_pos + 2], input[in_pos + 3]]);
    let deflate_len = in_pos - 2;
    in_pos += 4;

    if stored != adler.value() {
        return Err(Error::Zlib(format!(
            "adler32 校验失败: 流内 {:08x} != 实际 {:08x}（zlib 流范围 0..{}）",
            stored,
            adler.value(),
            in_pos
        )));
    }

    if let Some(d) = declared {
        if d as usize != out.len() {
            return Err(Error::SizeLie(format!(
                "声明大小 {} 与实际解压大小 {} 不一致",
                d,
                out.len()
            )));
        }
    }

    Ok(InflateOutcome {
        consumed: in_pos,
        deflate_len,
        data: out,
        declared,
    })
}

/// 带 zlib 包装的压缩（供测试构造 pack/loose 使用）。
pub fn deflate_zlib(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}
