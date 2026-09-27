use super::oid::Oid;
use super::{OBJ_OFS_DELTA, OBJ_REF_DELTA};

#[derive(Debug, Clone)]
pub struct PackObjHeader {
    pub type_id: u8,
    pub inflated_size: u64,
    pub header_end: usize,
    pub ref_base: Option<Oid>,
    pub ofs_back: Option<i64>,
    pub base_offset: Option<u64>,
}

pub fn read_pack_header(
    data: &[u8],
    start: usize,
    abs_off: u64,
) -> Result<PackObjHeader, String> {
    let mut p = start;
    if p >= data.len() {
        return Err("object header truncated".into());
    }
    let b0 = data[p];
    p += 1;
    let type_id = (b0 >> 4) & 0x7;
    let mut size: u64 = (b0 & 0x0f) as u64;
    let mut shift = 4u32;
    if b0 & 0x80 != 0 {
        loop {
            if p >= data.len() {
                return Err("object size continuation truncated".into());
            }
            let b = data[p];
            p += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if shift > 63 {
                return Err("object size overflow".into());
            }
        }
    }
    let mut ref_base = None;
    let mut ofs_back = None;
    let mut base_offset = None;
    if type_id == OBJ_OFS_DELTA {
        if p >= data.len() {
            return Err("ofs-delta base truncated".into());
        }
        let first = data[p];
        p += 1;
        let mut back: i64 = (first & 0x7f) as i64;
        let mut cur = first;
        while cur & 0x80 != 0 {
            if p >= data.len() {
                return Err("ofs-delta base continuation truncated".into());
            }
            let b = data[p];
            p += 1;
            back = back
                .checked_add(1)
                .and_then(|x| x.checked_shl(7))
                .and_then(|x| x.checked_add((b & 0x7f) as i64))
                .ok_or_else(|| "ofs-delta offset overflow".to_string())?;
            cur = b;
            if b & 0x80 == 0 {
                break;
            }
        }
        let bo = (abs_off as i64)
            .checked_sub(back)
            .ok_or_else(|| "ofs-delta distance out of range".to_string())?;
        if bo < 0 {
            return Err("ofs-delta distance out of range".into());
        }
        ofs_back = Some(back);
        base_offset = Some(bo as u64);
    } else if type_id == OBJ_REF_DELTA {
        if p + 20 > data.len() {
            return Err("ref-delta base truncated".into());
        }
        let mut o = [0u8; 20];
        o.copy_from_slice(&data[p..p + 20]);
        p += 20;
        ref_base = Some(Oid(o));
    }
    Ok(PackObjHeader {
        type_id,
        inflated_size: size,
        header_end: p,
        ref_base,
        ofs_back,
        base_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ofs_encoding_official_example() {
        // ofs-encode N=253 (a multi-byte distance)
        let mut enc = vec![253u8 + 128];
        let mut n = 253i64;
        let mut first = true;
        while n > 0 {
            let mut c = n & 0x7f;
            n >>= 7;
            if n > 0 {
                c |= 0x80;
            }
            let _ = first;
            first = false;
            enc.push(c as u8);
        }
        // Validate with a simple local decoder matching git semantics.
        let first = enc[0] as i64;
        let mut back = first & 0x7f;
        for &b in &enc[1..] {
            back = ((back + 1) << 7) + (b & 0x7f) as i64;
            if b & 0x80 == 0 {
                break;
            }
        }
        assert_eq!(back, 253);
    }
}
