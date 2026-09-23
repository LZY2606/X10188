use crate::gitid::sha1_object;
use crate::types::Kind;
use crate::zlibutil::{inflate_capped, InflateOutcome};

pub struct LooseObject {
    pub kind: Kind,
    pub content: Vec<u8>,
    pub computed_oid: [u8; 20],
}

pub fn parse_loose(data: &[u8], cap: u64) -> Result<LooseObject, String> {
    let (outcome, inflated) = inflate_capped(data, 0, cap);
    if !matches!(outcome, InflateOutcome::Exact { .. }) {
        return Err(format!("loose inflate failed: {:?}", outcome));
    }
    let nul = inflated
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| "loose object missing NUL header".to_string())?;
    let header = std::str::from_utf8(&inflated[..nul]).map_err(|e| e.to_string())?;
    let mut parts = header.split(' ');
    let kind_s = parts.next().ok_or("loose: missing type")?;
    let size_s = parts.next().ok_or("loose: missing size")?;
    let declared: usize = size_s.parse().map_err(|_| "loose: bad size".to_string())?;
    let content = inflated[nul + 1..].to_vec();
    if content.len() != declared {
        return Err(format!(
            "loose size_lie: header {} body {}",
            declared,
            content.len()
        ));
    }
    let kind = match kind_s {
        "commit" => Kind::Commit,
        "tree" => Kind::Tree,
        "blob" => Kind::Blob,
        "tag" => Kind::Tag,
        other => return Err(format!("loose: unknown type {}", other)),
    };
    let computed = sha1_object(kind.name(), &content);
    Ok(LooseObject {
        kind,
        content,
        computed_oid: computed,
    })
}
