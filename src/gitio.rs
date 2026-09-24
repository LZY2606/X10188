use crate::types::ObjectType;
use flate2::{Decompress, FlushCompress, FlushDecompress, Compress};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct Inflated {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub adler_ok: bool,
}

pub fn inflate_zlib(input: &[u8], max_bytes: usize) -> Result<Inflated, String> {
    if input.len() < 2 {
        return Err("zlib stream is shorter than two bytes".into());
    }
    if input[0] & 0x0f != 8 || (usize::from(input[0]) * 256 + usize::from(input[1])) % 31 != 0 {
        return Err("invalid zlib header".into());
    }
    let mut decoder = Decompress::new(true);
    let mut output = Vec::new();
    let mut used = 0usize;
    loop {
        if output.len() >= max_bytes {
            return Err(format!("inflated object exceeds {max_bytes} byte budget"));
        }
        let room = (max_bytes - output.len()).min(65536);
        let mut chunk = vec![0u8; room];
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder.decompress(
            &input[used..],
            &mut chunk,
            FlushDecompress::Finish,
        );
        used += (decoder.total_in() - before_in) as usize;
        let produced = (decoder.total_out() - before_out) as usize;
        output.extend_from_slice(&chunk[..produced]);
        match status {
            Ok(flate2::Status::StreamEnd) => break,
            Ok(_) if used == input.len() => return Err("truncated zlib stream".into()),
            Ok(_) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    let adler_ok = input
        .get(used.saturating_sub(4)..used)
        .map(|tail| {
            let mut hasher = crc32fast::Hasher::new_with_initial(1);
            hasher.update(&output);
            let mut bytes = [0u8; 4];
            hasher.finalize_into(&mut bytes);
            tail == bytes
        })
        .unwrap_or(false);
    Ok(Inflated {
        data: output,
        consumed: used,
        adler_ok,
    })
}

pub fn deflate_zlib(input: &[u8]) -> Vec<u8> {
    let mut encoder = Compress::new(flate2::Compression::default(), true);
    let mut output = vec![0u8; input.len() + 128];
    let status = encoder
        .compress_vec(input, &mut output, FlushCompress::Finish)
        .expect("zlib compression buffer is large enough");
    assert_eq!(status, flate2::Status::StreamEnd);
    output.truncate(encoder.total_out() as usize);
    output
}

pub fn read_git_size(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        let byte = *data.get(pos).ok_or("truncated size encoding")?;
        pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("size encoding is too large".into());
        }
    }
    Ok((value, pos))
}

pub fn encode_git_size(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return output;
        }
    }
}

pub fn common_header(object_type: ObjectType, len: usize) -> Vec<u8> {
    let mut header = object_type.as_str().as_bytes().to_vec();
    header.push(b' ');
    header.extend_from_slice(len.to_string().as_bytes());
    header.push(0);
    header
}

pub fn git_object_id(object_type: ObjectType, body: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(common_header(object_type, body.len()));
    hasher.update(body);
    hasher.finalize().into()
}

pub fn pack_entry_header(object_type: u8, size: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut byte = (size as u8 & 0x0f) | ((object_type & 7) << 4);
    let mut rest = size >> 4;
    if rest != 0 {
        byte |= 0x80;
    }
    bytes.push(byte);
    while rest != 0 {
        let mut next = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest != 0 {
            next |= 0x80;
        }
        bytes.push(next);
    }
    bytes
}

pub fn encode_ofs_negative(mut distance: u64) -> Vec<u8> {
    let mut bytes = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance != 0 {
        distance -= 1;
        bytes.push(0x80 | ((distance >> 0) & 0x7f) as u8);
        distance >>= 7;
    }
    bytes.reverse();
    if let Some(first) = bytes.first_mut() {
        *first |= 0x80;
    }
    bytes
}

pub fn read_ofs_distance(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut byte = *data.get(pos).ok_or("truncated ofs-delta")?;
    pos += 1;
    if byte & 0x80 == 0 {
        return Err("ofs-delta continuation bit is missing".into());
    }
    let mut value = u64::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        byte = *data.get(pos).ok_or("truncated ofs-delta distance")?;
        pos += 1;
        value = ((value + 1) << 7) | u64::from(byte & 0x7f);
    }
    Ok((value, pos))
}

pub fn read_u32(data: &[u8], pos: usize) -> Result<u32, String> {
    data.get(pos..pos + 4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .ok_or_else(|| "truncated u32".into())
}

pub fn delta_data(declared_base_size: u64, declared_result_size: u64, instructions: &[(u8, u64, u64, Vec<u8>)]) -> Vec<u8> {
    let mut data = encode_git_size(declared_base_size);
    data.extend(encode_git_size(declared_result_size));
    for (op, offset, size, literal) in instructions {
        data.push(*op);
        if *op == 0x80 {
            for shift in (0..4).rev() {
                let value = (*offset >> (shift * 8)) as u8;
                if value != 0 {
                    data.push(value);
                }
            }
            for shift in (0..3).rev() {
                let value = (*size >> (shift * 8)) as u8;
                if value != 0 {
                    data.push(value);
                }
            }
        } else {
            data.extend_from_slice(literal);
        }
    }
    data
}
