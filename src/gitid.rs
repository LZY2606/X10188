// Minimal Git object id (SHA-1) computation without external git.
use std::io::Read;

pub fn sha1_object(kind: &str, content: &[u8]) -> [u8; 20] {
    let header = format!("{} {}\0", kind, content.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hasher.finalize()
}

pub fn deflate_object(kind: &str, content: &[u8]) -> Vec<u8> {
    let header = format!("{} {}\0", kind, content.len());
    let mut all = Vec::with_capacity(header.len() + content.len());
    all.extend_from_slice(header.as_bytes());
    all.extend_from_slice(content);
    let mut out = Vec::new();
    let mut enc = flate2::read::ZlibEncoder::new(
        &all[..],
        flate2::Compression::default(),
    );
    enc.read_to_end(&mut out).unwrap();
    out
}

// ---- minimal SHA-1 (FIPS 180-1) ----
pub struct Sha1 {
    h: [u32; 5],
    buf: Vec<u8>,
    len: u64,
}

impl Sha1 {
    pub fn new() -> Self {
        Sha1 {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buf: Vec::new(),
            len: 0,
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.len = self.len.wrapping_add((data.len() as u64) * 8);
        self.buf.extend_from_slice(data);
        while self.buf.len() >= 64 {
            let block: Vec<u8> = self.buf.drain(..64).collect();
            self.block(&block);
        }
    }
    pub fn finalize(mut self) -> [u8; 20] {
        self.buf.push(0x80);
        while self.buf.len() % 64 != 56 {
            self.buf.push(0);
        }
        self.buf.extend_from_slice(&self.len.to_be_bytes());
        while self.buf.len() >= 64 {
            let block: Vec<u8> = self.buf.drain(..64).collect();
            self.block(&block);
        }
        let mut out = [0u8; 20];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
    fn block(&mut self, b: &[u8]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                b[i * 4],
                b[i * 4 + 1],
                b[i * 4 + 2],
                b[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.h;
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        for (i, x) in [a, b, c, d, e].iter().enumerate() {
            self.h[i] = self.h[i].wrapping_add(*x);
        }
    }
}
