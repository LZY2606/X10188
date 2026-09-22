use flate2::Decompress;

use crate::error::PError;

/// zlib 流解压结果：解出的字节 + 消费的压缩字节数（用于定位 zlib 边界）。
#[derive(Debug, Clone)]
pub struct Inflated {
    pub data: Vec<u8>,
    /// 压缩数据在输入缓冲区中占用的字节数（zlib 边界）。
    pub consumed: usize,
}

/// 从 `src` 起始处解压一个 zlib 流。
///
/// - `expect_size`：pack/delta 头声明的解压后大小；若解出的真实长度不同则报 SizeSpoof。
/// - `hard_limit`：无论声明多少，解出长度超过该值立即中止（防 zip bomb）。
pub fn inflate_stream(
    src: &[u8],
    expect_size: u64,
    hard_limit: u64,
) -> Result<Inflated, PError> {
    let mut dec = Decompress::new(true);
    // 以声明大小为参考预分配，但设置上限，避免伪造一个超大声明直接 OOM。
    let cap = std::cmp::min(expect_size, hard_limit) as usize;
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(1 << 20));
    let mut input_pos: usize = 0;
    let chunk: usize = 16 * 1024;

    loop {
        let avail_in_before = dec.total_in();
        let in_buf = &src[input_pos..];
        if in_buf.is_empty() && !out.is_empty() {
            // 可能仍需更多输出空间才能触发 stream-end，继续给输出缓冲。
        } else if in_buf.is_empty() {
            return Err(PError::Zlib("压缩流在结束前耗尽输入".to_string()));
        }
        let prev_in = dec.total_in();
        let out_len_before = out.len();
        out.reserve(chunk.min(1 << 16));
        let spare = out.spare_capacity_mut();
        let out_slice =
            unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) };

        let res = dec.decompress(in_buf, out_slice, flate2::FlushDecompress::None);
        let consumed_now = (dec.total_in() - prev_in) as usize;
        input_pos += consumed_now;
        let _ = avail_in_before;
        let written = (dec.total_out() as usize) - out_len_before;
        unsafe {
            out.set_len(out_len_before + written);
        }

        if (out.len() as u64) > hard_limit {
            return Err(PError::InflateLimit {
                limit: hard_limit,
                actual: out.len() as u64,
            });
        }

        match res {
            Ok(flate2::Status::Ok) => {
                // 若没有任何进展且输入耗尽，避免死循环。
                if consumed_now == 0 && written == 0 {
                    return Err(PError::Zlib("解压无进展".to_string()));
                }
            }
            Ok(flate2::Status::StreamEnd) => break,
            Ok(flate2::Status::BufError) => {
                // 仅当缓冲区满时正常；这里每次都给了大块，出现则视为异常。
                if consumed_now == 0 && written == 0 {
                    return Err(PError::Zlib("缓冲区异常且无进展".to_string()));
                }
            }
            Err(e) => return Err(PError::Zlib(e.to_string())),
        }
    }

    let actual = out.len() as u64;
    if actual != expect_size {
        return Err(PError::SizeSpoof {
            declared: expect_size,
            actual,
        });
    }

    Ok(Inflated {
        data: out,
        consumed: input_pos,
    })
}

/// 宽松解压：不校验声明大小，用于 loose 与“先探测再判断”的场景。
pub fn inflate_unbounded(src: &[u8], hard_limit: u64) -> Result<Inflated, PError> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut input_pos = 0usize;
    let chunk = 16 * 1024;
    loop {
        let prev_in = dec.total_in();
        let out_len_before = out.len();
        out.reserve(chunk);
        let spare = out.spare_capacity_mut();
        let out_slice =
            unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) };
        let in_buf = &src[input_pos..];
        let res = dec.decompress(in_buf, out_slice, flate2::FlushDecompress::None);
        input_pos += (dec.total_in() - prev_in) as usize;
        let written = dec.total_out() as usize - out_len_before;
        unsafe {
            out.set_len(out_len_before + written);
        }
        if out.len() as u64 > hard_limit {
            return Err(PError::InflateLimit {
                limit: hard_limit,
                actual: out.len() as u64,
            });
        }
        match res {
            Ok(flate2::Status::Ok) => {}
            Ok(flate2::Status::StreamEnd) => break,
            Ok(flate2::Status::BufError) => {
                if input_pos >= src.len() {
                    return Err(PError::Zlib("压缩流在结束前耗尽输入".to_string()));
                }
            }
            Err(e) => return Err(PError::Zlib(e.to_string())),
        }
    }
    Ok(Inflated {
        data: out,
        consumed: input_pos,
    })
}
