use flate2::Decompress;
use flate2::FlushDecompress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateOutcome {
    /// Exactly `declared` bytes produced and stream ended cleanly.
    Exact { consumed: usize, total_in: u64, total_out: u64 },
    /// Stream ended but produced fewer than declared bytes.
    Truncated { got: u64, declared: u64, consumed: usize },
    /// Output reached declared+1 bytes while stream not finished (size lie),
    /// or hit an explicit safety cap before stream end.
    Overflow { got: u64, declared: u64 },
    /// Stream error (bad data / half-way corruption).
    Error(String),
}

/// Inflate a zlib stream starting at `data[start]`.
/// `declared` is the size advertised by the object header / delta header.
/// Inflation stops after `declared + 1` output bytes so a lying header that
/// hides extra data is detected without unbounded allocation.
pub fn inflate_guarded(data: &[u8], start: usize, declared: u64) -> (InflateOutcome, Vec<u8>) {
    let limit = declared.saturating_add(1);
    let mut dec = Decompress::new(true);
    let mut out = Vec::new();
    let mut input_pos = start;
    let mut tmp = [0u8; 8192];
    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let in_slice = &data[input_pos..];
        if in_slice.is_empty() {
            return (InflateOutcome::Error("unexpected end of compressed data".into()), out);
        }
        let res = dec.decompress(in_slice, &mut tmp, FlushDecompress::None);
        let consumed = (dec.total_in() - before_in) as usize;
        input_pos += consumed;
        let produced = (dec.total_out() - before_out) as usize;
        out.extend_from_slice(&tmp[..produced]);
        if out.len() as u64 > limit {
            return (InflateOutcome::Overflow { got: out.len() as u64, declared }, out);
        }
        match res {
            Ok(FlushDecompress::StreamEnd) => {
                let got = dec.total_out();
                if got != declared {
                    return (
                        InflateOutcome::Truncated {
                            got,
                            declared,
                            consumed: input_pos - start,
                        },
                        out,
                    );
                }
                return (
                    InflateOutcome::Exact {
                        consumed: input_pos - start,
                        total_in: dec.total_in(),
                        total_out: got,
                    },
                    out,
                );
            }
            Ok(FlushDecompress::Ok) => {}
            Err(e) => return (InflateOutcome::Error(e.to_string()), out),
        }
    }
}

/// Inflate with no advertised size, capped by an absolute safety limit.
pub fn inflate_capped(data: &[u8], start: usize, cap: u64) -> (InflateOutcome, Vec<u8>) {
    let mut dec = Decompress::new(true);
    let mut out = Vec::new();
    let mut input_pos = start;
    let mut tmp = [0u8; 8192];
    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let in_slice = &data[input_pos..];
        if in_slice.is_empty() {
            return (InflateOutcome::Error("unexpected end of compressed data".into()), out);
        }
        let res = dec.decompress(in_slice, &mut tmp, FlushDecompress::None);
        let consumed = (dec.total_in() - before_in) as usize;
        input_pos += consumed;
        let produced = (dec.total_out() - before_out) as usize;
        out.extend_from_slice(&tmp[..produced]);
        if out.len() as u64 > cap {
            return (
                InflateOutcome::Overflow { got: out.len() as u64, declared: cap },
                out,
            );
        }
        match res {
            Ok(FlushDecompress::StreamEnd) => {
                return (
                    InflateOutcome::Exact {
                        consumed: input_pos - start,
                        total_in: dec.total_in(),
                        total_out: dec.total_out(),
                    },
                    out,
                )
            }
            Ok(FlushDecompress::Ok) => {}
            Err(e) => return (InflateOutcome::Error(e.to_string()), out),
        }
    }
}
