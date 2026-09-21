use crate::git::{bounded_inflate, git_object_id, InflateError, ObjType};

pub struct LooseOutcome {
    pub obj_type: ObjType,
    pub data: Vec<u8>,
    pub declared_size: u64,
    pub oid: [u8; 20],
}

pub enum LooseError {
    Corrupt(String),
    SizeSpoof { declared: u64, actual: u64 },
    TooLarge(u64),
    Truncated,
}

pub fn parse_loose(bytes: &[u8], hard_limit: u64) -> Result<LooseOutcome, LooseError> {
    let out = bounded_inflate(bytes, None, hard_limit).map_err(|e| match e {
        InflateError::Truncated => LooseError::Truncated,
        InflateError::Corrupt(m) => LooseError::Corrupt(m),
        InflateError::SizeSpoof { .. } => LooseError::Corrupt("内部错误".into()),
        InflateError::TooLarge { limit, .. } => LooseError::TooLarge(limit),
    })?;
    let nul = out
        .data
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| LooseError::Corrupt("loose 对象缺少 NUL 头分隔".into()))?;
    let header = std::str::from_utf8(&out.data[..nul])
        .map_err(|_| LooseError::Corrupt("loose 头不是合法 UTF-8".into()))?;
    let (type_str, size_str) = header
        .split_once(' ')
        .ok_or_else(|| LooseError::Corrupt("loose 头格式应为 <type> <size>".into()))?;
    let typ = ObjType::named(type_str)
        .filter(|t| !t.is_delta())
        .ok_or_else(|| LooseError::Corrupt(format!("loose 头类型非法: {}", type_str)))?;
    let declared: u64 = size_str
        .parse()
        .map_err(|_| LooseError::Corrupt(format!("loose 头大小非法: {}", size_str)))?;
    let data = out.data[nul + 1..].to_vec();
    if data.len() as u64 != declared {
        return Err(LooseError::SizeSpoof {
            declared,
            actual: data.len() as u64,
        });
    }
    let oid = git_object_id(typ.base_type().unwrap(), &data);
    Ok(LooseOutcome {
        obj_type: typ,
        data,
        declared_size: declared,
        oid,
    })
}
