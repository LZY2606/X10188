use crate::inflate::{self, InflateIssue};
use crate::oid::{self, Oid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjKind {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjKind {
    pub fn from_code(code: u8) -> Option<ObjKind> {
        Some(match code {
            1 => ObjKind::Commit,
            2 => ObjKind::Tree,
            3 => ObjKind::Blob,
            4 => ObjKind::Tag,
            6 => ObjKind::OfsDelta,
            7 => ObjKind::RefDelta,
            _ => return None,
        })
    }

    pub fn from_name(name: &str) -> Option<ObjKind> {
        Some(match name {
            "commit" => ObjKind::Commit,
            "tree" => ObjKind::Tree,
            "blob" => ObjKind::Blob,
            "tag" => ObjKind::Tag,
            "ofs-delta" => ObjKind::OfsDelta,
            "ref-delta" => ObjKind::RefDelta,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ObjKind::Commit => "commit",
            ObjKind::Tree => "tree",
            ObjKind::Blob => "blob",
            ObjKind::Tag => "tag",
            ObjKind::OfsDelta => "ofs-delta",
            ObjKind::RefDelta => "ref-delta",
        }
    }

    pub fn is_delta(&self) -> bool {
        matches!(self, ObjKind::OfsDelta | ObjKind::RefDelta)
    }
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub index: usize,
    pub offset: u64,
    pub header_len: u64,
    pub kind: ObjKind,
    pub declared_size: u64,
    pub ofs_distance: Option<u64>,
    pub base_offset: Option<u64>,
    pub base_oid: Option<Oid>,
    pub data_start: u64,
    pub data_end: Option<u64>,
    pub inflated_len: Option<u64>,
    pub issue: Option<String>,
}

#[derive(Debug)]
pub struct PackParse {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer: Oid,
    pub trailer_ok: bool,
    pub stopped_early: bool,
}

fn parse_type_size(bytes: &[u8], mut pos: usize) -> Option<(u8, u64, usize)> {
    let mut c = *bytes.get(pos)?;
    pos += 1;
    let ty = (c >> 4) & 0x07;
    let mut size = (c & 0x0f) as u64;
    let mut shift = 4u32;
    while c & 0x80 != 0 {
        c = *bytes.get(pos)?;
        pos += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some((ty, size, pos))
}

fn parse_ofs_distance(bytes: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut c = *bytes.get(pos)?;
    pos += 1;
    let mut value = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        c = *bytes.get(pos)?;
        pos += 1;
        value = value.checked_add(1)?.checked_shl(7)? | (c & 0x7f) as u64;
    }
    Some((value, pos))
}

fn merge_issue(existing: Option<String>, extra: String) -> Option<String> {
    match existing {
        Some(e) => Some(format!("{e}; {extra}")),
        None => Some(extra),
    }
}

pub fn parse_pack(bytes: &[u8]) -> Result<PackParse, String> {
    if bytes.len() < 12 + 20 {
        return Err("文件太小, 不是合法的 pack".into());
    }
    if &bytes[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    let trailer = Oid(bytes[bytes.len() - 20..].try_into().unwrap());
    let trailer_ok = oid::sha1_of(&bytes[..bytes.len() - 20]) == trailer;
    let end = bytes.len() - 20;
    let mut pos = 12usize;
    let mut entries = Vec::new();
    let mut stopped_early = false;
    for i in 0..count {
        if pos >= end {
            stopped_early = true;
            break;
        }
        let entry_offset = pos as u64;
        let Some((ty, size, after_hdr)) = parse_type_size(bytes, pos) else {
            stopped_early = true;
            break;
        };
        pos = after_hdr;
        let Some(kind) = ObjKind::from_code(ty) else {
            stopped_early = true;
            break;
        };
        let mut ofs_distance = None;
        let mut base_offset = None;
        let mut base_oid = None;
        let mut issue = None;
        match kind {
            ObjKind::OfsDelta => match parse_ofs_distance(bytes, pos) {
                Some((dist, p2)) => {
                    pos = p2;
                    ofs_distance = Some(dist);
                    if dist == 0 || dist as usize > entry_offset as usize - 12 {
                        issue = merge_issue(
                            issue,
                            format!("ofs 距离 {dist} 越界 (对象起始偏移 {entry_offset})"),
                        );
                    } else {
                        base_offset = Some(entry_offset - dist);
                    }
                }
                None => {
                    stopped_early = true;
                    break;
                }
            },
            ObjKind::RefDelta => {
                if pos + 20 > end {
                    stopped_early = true;
                    break;
                }
                base_oid = Some(Oid(bytes[pos..pos + 20].try_into().unwrap()));
                pos += 20;
            }
            _ => {}
        }
        let header_len = pos as u64 - entry_offset;
        let data_start = pos as u64;
        let cap = size.min(inflate::HARD_CAP);
        match inflate::inflate_bounded(&bytes[pos..end], cap) {
            Ok((out, used)) => {
                let mut iss = issue.take();
                if out.len() as u64 != size {
                    iss = merge_issue(
                        iss,
                        InflateIssue::SizeMismatch {
                            declared: size,
                            actual: out.len() as u64,
                        }
                        .to_string(),
                    );
                }
                entries.push(PackEntry {
                    index: i as usize,
                    offset: entry_offset,
                    header_len,
                    kind,
                    declared_size: size,
                    ofs_distance,
                    base_offset,
                    base_oid,
                    data_start,
                    data_end: Some((pos + used) as u64),
                    inflated_len: Some(out.len() as u64),
                    issue: iss,
                });
                pos += used;
            }
            Err(err) => {
                let iss = merge_issue(issue.take(), err.to_string());
                entries.push(PackEntry {
                    index: i as usize,
                    offset: entry_offset,
                    header_len,
                    kind,
                    declared_size: size,
                    ofs_distance,
                    base_offset,
                    base_oid,
                    data_start,
                    data_end: None,
                    inflated_len: None,
                    issue: iss,
                });
                stopped_early = true;
                break;
            }
        }
    }
    if entries.len() < count as usize && !stopped_early {
        stopped_early = true;
    }
    Ok(PackParse {
        version,
        declared_count: count,
        entries,
        trailer,
        trailer_ok,
        stopped_early,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{build_pack, make_delta, TestEntry};

    #[test]
    fn parses_layout_and_zlib_boundary() {
        let base = b"alpha base content".to_vec();
        let target = b"alpha base content plus delta tail".to_vec();
        let delta = make_delta(&base, &target);
        let (pack, offsets) = build_pack(&[
            TestEntry::full("blob", &base),
            TestEntry::full("blob", b"second blob"),
            TestEntry::ofs(0, delta),
        ]);
        let parsed = parse_pack(&pack).unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert!(parsed.trailer_ok);
        assert_eq!(parsed.entries[0].offset, 12);
        assert_eq!(parsed.entries[1].offset, offsets[1]);
        let e0 = &parsed.entries[0];
        assert_eq!(e0.kind, ObjKind::Blob);
        assert_eq!(e0.inflated_len, Some(base.len() as u64));
        let e2 = &parsed.entries[2];
        assert_eq!(e2.kind, ObjKind::OfsDelta);
        assert_eq!(e2.base_offset, Some(offsets[0]));
        assert_eq!(e2.data_end.unwrap(), pack.len() as u64 - 20);
    }
}
