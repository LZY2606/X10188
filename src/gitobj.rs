use sha1::{Digest, Sha1};

pub fn type_name(code: u8) -> &'static str {
    match code {
        1 => "commit",
        2 => "tree",
        3 => "blob",
        4 => "tag",
        6 => "ofs_delta",
        7 => "ref_delta",
        _ => "unknown",
    }
}

pub fn type_code(name: &str) -> Option<u8> {
    Some(match name {
        "commit" => 1,
        "tree" => 2,
        "blob" => 3,
        "tag" => 4,
        _ => return None,
    })
}

pub fn object_id(otype: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", otype, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    hex::encode(Sha1::digest(data))
}
