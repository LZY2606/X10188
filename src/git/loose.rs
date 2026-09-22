//! loose object 解析：zlib("<type> <size>\0" + content)
//! 不相信头部声明的 size，以实际解压内容重新计算 Git object id。

use super::{git_object_id, GitType};
use super::zlib::inflate_one;

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub t: GitType,
    pub declared_size: u64,
    pub content: Vec<u8>,
    /// 头声明 size 与真实内容长度不符
    pub size_spoof: bool,
    pub problem: Option<String>,
}

pub fn parse_loose(raw: &[u8]) -> Result<LooseObject, String> {
    // loose 没有外部 size，用安全上限作为声明基准
    let o = inflate_one(raw, 0, u64::MAX, 512 * 1024 * 1024)
        .map_err(|e| format!("loose 对象解压失败: {e:?}"))?;
    let data = o.data;
    let nul = data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose 对象缺少 NUL 头分隔".to_string())?;
    let header = std::str::from_utf8(&data[..nul])
        .map_err(|_| "loose 对象头不是合法 UTF-8".to_string())?;
    let mut it = header.split(' ');
    let type_name = it.next().ok_or("loose 对象头缺少类型")?;
    let size_str = it.next().ok_or("loose 对象头缺少大小")?;
    if it.next().is_some() {
        return Err("loose 对象头字段过多".into());
    }
    let t = GitType::from_name(type_name.as_bytes())
        .ok_or_else(|| format!("loose 对象类型未知: {type_name}"))?;
    let declared_size: u64 = size_str
        .parse()
        .map_err(|_| format!("loose 对象大小不是数字: {size_str}"))?;
    let content = data[nul + 1..].to_vec();
    let mut problem = None;
    let mut size_spoof = false;
    if declared_size != content.len() as u64 {
        size_spoof = true;
        problem = Some(format!(
            "loose 头声明 {declared_size} 字节，实际内容 {} 字节",
            content.len()
        ));
    }
    Ok(LooseObject {
        t,
        declared_size,
        content,
        size_spoof,
        problem,
    })
}

/// 重新计算 loose 对象的 git object id。
pub fn recompute_oid(o: &LooseObject) -> [u8; 20] {
    git_object_id(o.t, &o.content)
}
