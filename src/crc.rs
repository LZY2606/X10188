pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = crc & 1;
            crc >>= 1;
            if mask != 0 {
                crc ^= 0xedb8_8320;
            }
        }
    }
    !crc
}
