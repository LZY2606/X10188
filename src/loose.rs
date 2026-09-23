//! Loose git object parsing: zlib(`<type> <size>\0<content>`).

use flate2::{Decompress, FlushDecompress};

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub kind: String,
    pub content: Vec<u8>,
    pub declared_size: usize,
    pub issue: Option<String>,
}

pub fn parse_loose(data: &[u8]) -> LooseObject {
    let mut dec = Decompress::new(true);
    let mut raw = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let mut input_pos = 0usize;
    let result = loop {
        let in_before = dec.total_in();
        let out_before = dec.total_out();
        let st = match dec.decompress(
            &data[input_pos..],
            &mut chunk,
            FlushDecompress::Finish,
        ) {
            Ok(st) => st,
            Err(e) => break Err(format!("zlib error: {e}")),
        };
        let consumed = (dec.total_in() - in_before) as usize;
        input_pos += consumed;
        let produced = (dec.total_out() - out_before) as usize;
        raw.extend_from_slice(&chunk[..produced]);
        if raw.len() > 512 * 1024 * 1024 {
            break Err("loose object exceeds hard cap".into());
        }
        if st == flate2::Status::StreamEnd {
            break Ok(());
        }
    };
    if let Err(e) = result {
        return LooseObject {
            kind: String::new(),
            content: Vec::new(),
            declared_size: 0,
            issue: Some(e),
        };
    }

    let nul = match raw.iter().position(|&b| b == 0) {
        Some(i) => i,
        None => {
            return LooseObject {
                kind: String::new(),
                content: Vec::new(),
                declared_size: 0,
                issue: Some("loose object header missing NUL".into()),
            }
        }
    };
    let header = String::from_utf8_lossy(&raw[..nul]);
    let mut parts = header.splitn(2, ' ');
    let kind = parts.next().unwrap_or("").to_string();
    let size: usize = parts
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);
    let content = raw[nul + 1..].to_vec();
    let issue = if !matches!(kind.as_str(), "commit" | "tree" | "blob" | "tag") {
        Some(format!("unknown loose object type {kind:?}"))
    } else if size != content.len() {
        Some(format!(
            "loose size header {size} does not match content length {}",
            content.len()
        ))
    } else {
        None
    };
    LooseObject { kind, content, declared_size: size, issue }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Pack,
    Idx,
    Loose,
    Unknown,
}

pub fn detect_kind(filename: &str, data: &[u8]) -> FileKind {
    if data.len() >= 4 && &data[0..4] == b"PACK" {
        return FileKind::Pack;
    }
    if data.len() >= 8 && &data[0..4] == b"\xfftOc" {
        return FileKind::Idx;
    }
    if data.len() >= 256 * 4 + 8 {
        let mut monotonic = true;
        let mut prev = u32::from_be_bytes(data[0..4].try_into().unwrap());
        for i in 1..256 {
            let v = u32::from_be_bytes(data[i * 4..i * 4 + 4].try_into().unwrap());
            if v < prev {
                monotonic = false;
                break;
            }
            prev = v;
        }
        if monotonic && prev < 5_000_000 {
            return FileKind::Idx;
        }
    }
    if looks_like_zlib_object(data) {
        return FileKind::Loose;
    }
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".pack") {
        FileKind::Pack
    } else if lower.ends_with(".idx") {
        FileKind::Idx
    } else {
        FileKind::Unknown
    }
}

fn looks_like_zlib_object(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let cmf = data[0];
    let flg = data[1];
    if cmf & 0x0f != 8 {
        return false;
    }
    if (cmf as u16 * 256 + flg as u16) % 31 != 0 {
        return false;
    }
    let mut dec = Decompress::new(true);
    let mut out = vec![0u8; 256];
    matches!(
        dec.decompress(&data[..data.len().min(64)], &mut out, FlushDecompress::None),
        Ok(flate2::Status::Ok | flate2::Status::StreamEnd | flate2::Status::BufError)
    )
}
