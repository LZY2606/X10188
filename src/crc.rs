static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();

fn table() -> &'static [u32; 256] {
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for n in 0..256u32 {
            let mut c = n;
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = 0xedb88320 ^ (c >> 1);
                } else {
                    c >>= 1;
                }
            }
            t[n as usize] = c;
        }
        t
    })
}

pub fn crc32(data: &[u8]) -> u32 {
    let t = table();
    let mut c: u32 = 0xffff_ffff;
    for &b in data {
        c = t[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffff_ffff
}
