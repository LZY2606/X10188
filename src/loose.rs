use crate::git::{inflate_at, GitError, GitObject, ObjectType};

pub fn parse_loose(data: &[u8]) -> Result<(GitObject, usize), GitError> {
    let stream = inflate_at(data, 0)?;
    let nul = stream
        .data
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| GitError::BadHeader("loose object missing NUL".into()))?;
    let header = std::str::from_utf8(&stream.data[..nul])
        .map_err(|_| GitError::BadHeader("loose header is not UTF-8".into()))?;
    let (type_name, size_text) = header
        .split_once(' ')
        .ok_or_else(|| GitError::BadHeader("loose header missing size".into()))?;
    let kind = match type_name {
        "blob" => ObjectType::Blob,
        "tree" => ObjectType::Tree,
        "commit" => ObjectType::Commit,
        "tag" => ObjectType::Tag,
        _ => return Err(GitError::BadHeader(format!("unknown type {type_name}"))),
    };
    let declared = size_text
        .parse::<usize>()
        .map_err(|_| GitError::BadHeader("invalid loose size".into()))?;
    let content = stream.data[nul + 1..].to_vec();
    if content.len() != declared {
        return Err(GitError::SizeMismatch {
            declared,
            actual: content.len(),
        });
    }
    Ok((GitObject::new(kind, content), stream.consumed))
}
