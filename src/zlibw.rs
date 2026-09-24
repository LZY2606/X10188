use crate::error::{Error, ErrorCode, R};
use flate2::{Decompress, FlushDecompress};

/// Result of inflating a zlib stream embedded inside a larger buffer:
/// the inflated bytes plus how many *compressed* bytes were consumed.
pub fn inflate_at(input: &[u8], cap: usize) -> R<(Vec<u8>, usize)> {
    let mut dec = Decompress::new(true);
    let mut out = Vec::with_capacity(256.min(cap));
    let mut consumed_total = 0usize;
    loop {
        if out.len() > cap {
            return Err(Error::new(
                ErrorCode::InflateTooLarge,
                format!("inflated stream exceeds hard cap of {} bytes", cap),
            ));
        }
        if out.capacity() == out.len() {
            let grow = (out.len() * 2).max(1024).min(cap + 1);
            out.reserve(grow);
        }
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let iresult = dec.decompress_vec(&input[consumed_total..], &mut out, FlushDecompress::Finish);
        consumed_total += (dec.total_in() - before_in) as usize;
        let produced = (dec.total_out() - before_out) as usize;
        match iresult {
            Ok(flate2::Status::StreamEnd) => {
                debug_assert_eq!(produced + (out.len() - produced), out.len());
                return Ok((out, consumed_total));
            }
            Ok(flate2::Status::Ok) => {
                if consumed_total >= input.len() && out.len() == dec.total_out() as usize {
                    // Need more input but there is none.
                    return Err(Error::new(ErrorCode::ZlibError, "zlib stream truncated"));
                }
                continue;
            }
            Ok(flate2::Status::BufError) => {
                // Output buffer full: decompress_vec resets the spare; grow.
                if produced == 0 && out.len() == dec.total_out() as usize {
                    out.reserve((out.len() * 2).max(1024));
                }
                continue;
            }
            Err(e) => {
                return Err(Error::new(ErrorCode::ZlibError, format!("zlib: {}", e)));
            }
        }
    }
}
