//! 标准 CRC-32（IEEE 802.3），与 Git index 中条目 CRC 的算法一致。

fn table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut j = 0;
        while j < 8 {
            c = if c & 1 != 0 { 0xedb88320 ^ (c >> 1) } else { c >> 1 };
            j += 1;
        }
        t[i as usize] = c;
        i += 1;
    }
    t
}

pub fn crc32(data: &[u8]) -> u32 {
    let t = table();
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc = t[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}
