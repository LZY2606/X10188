use sha1::{Digest, Sha1};
use sha2::Sha256;

pub fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn be32(d: &[u8]) -> u32 {
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

pub fn be64(d: &[u8]) -> u64 {
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

pub fn git_oid(ty: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{ty} {}\0", content.len()).as_bytes());
    h.update(content);
    hex(&h.finalize())
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex(&h.finalize())
}

pub fn now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

pub fn short(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn is_text(data: &[u8]) -> bool {
    if data.contains(&0) {
        return false;
    }
    std::str::from_utf8(data).is_ok()
}

pub fn hexdump(data: &[u8], max: usize) -> String {
    let mut out = String::new();
    let n = data.len().min(max);
    for (i, chunk) in data[..n].chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", i * 16));
        for b in chunk {
            out.push_str(&format!("{b:02x} "));
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        out.push_str(" |");
        for b in chunk {
            let c = *b as char;
            out.push(if c.is_ascii_graphic() || c == ' ' { c } else { '.' });
        }
        out.push_str("|\n");
    }
    if data.len() > max {
        out.push_str(&format!("... (共 {} 字节，仅显示前 {})\n", data.len(), max));
    }
    out
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
