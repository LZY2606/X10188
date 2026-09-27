//! 纯 Rust 解析 Git pack v2：header、对象头、ofs-delta / ref-delta、
//! zlib 流边界、pack trailer SHA-1。所有偏移都是相对 pack 文件起点的原始偏移。

use flate2::{Decompress, FlushDecompress, Status};
use serde::{Deserialize, Serialize};

use crate::Oid;

/// 解压后为伪造大小保留的证据前缀长度。
const SPOOF_EVIDENCE_CAP: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackEntryKind {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl PackEntryKind {
    pub fn is_delta(&self) -> bool {
        matches!(self, PackEntryKind::OfsDelta | PackEntryKind::RefDelta)
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            PackEntryKind::Commit => "commit",
            PackEntryKind::Tree => "tree",
            PackEntryKind::Blob => "blob",
            PackEntryKind::Tag => "tag",
            PackEntryKind::OfsDelta => "ofs-delta",
            PackEntryKind::RefDelta => "ref-delta",
        }
    }
    fn from_bits(b: u8) -> Option<PackEntryKind> {
        match b {
            1 => Some(PackEntryKind::Commit),
            2 => Some(PackEntryKind::Tree),
            3 => Some(PackEntryKind::Blob),
            4 => Some(PackEntryKind::Tag),
            6 => Some(PackEntryKind::OfsDelta),
            7 => Some(PackEntryKind::RefDelta),
            _ => None,
        }
    }
}

/// 单个 entry 解压结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseOutcome {
    /// 正常解压且声明大小与实际一致。
    Ok,
    /// 声明大小与实际解压长度不一致（大小欺骗 / 损坏）。
    SizeSpoof { declared: u64, actual: u64 },
    /// zlib 流损坏，无法定位边界；解析在此 entry 终止。
    ZlibCorrupt { message: String },
    /// 解压输出超过硬上限，解析在此 entry 终止。
    TooLarge { actual: u64, cap: u64 },
    /// 输入在 zlib 流结束前耗尽。
    TruncatedZlib,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackEntry {
    /// entry 头起始偏移。
    pub offset: u64,
    /// 压缩数据起始偏移（头部之后）。
    pub data_offset: u64,
    /// 头中声明的（解压）大小。
    pub declared_size: u64,
    pub kind: PackEntryKind,
    /// ofs-delta：负距离（base 位于 offset - negative）。
    pub ofs_negative: Option<u64>,
    /// ref-delta：头部记录的 base oid。
    pub ref_base: Option<Oid>,
    /// 解压出的负载（非 delta 为对象体；delta 为 delta 指令数据）。
    /// 大小欺骗时仅保留证据前缀。
    pub payload: Vec<u8>,
    /// 压缩负载的 CRC32（idx 校验用）。
    pub crc32: u32,
    /// 该 entry 占用的总字节数（含头部与压缩负载）。
    pub entry_len: u64,
    pub outcome: ParseOutcome,
    /// 实际 zlib 边界（下一个 entry 起始偏移）。
    pub next_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    /// trailer 20 字节 SHA-1（按文件内容）。
    pub trailer: Oid,
    pub trailer_offset: u64,
    pub trailer_ok: bool,
    /// 文件中的尾部杂散字节数（正常应为 0）。
    pub trailing_garbage: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackParseError {
    BadMagic { at: usize },
    UnsupportedVersion { version: u32 },
    Truncated { at: usize, need: usize, have: usize },
    BadTypeBits { offset: u64, bits: u8 },
    OfsOutOfPack { offset: u64, base: i64 },
    ZlibFatal { offset: u64, message: String },
    InflateTooLarge { offset: u64, actual: u64, cap: u64 },
    TrailerMissing { at: usize },
}

impl std::fmt::Display for PackParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for PackParseError {}

struct Cur<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn need(&self, n: usize) -> Result<(), PackParseError> {
        if self.p + n > self.d.len() {
            Err(PackParseError::Truncated {
                at: self.p,
                need: n,
                have: self.d.len().saturating_sub(self.p),
            })
        } else {
            Ok(())
        }
    }
    fn u8(&mut self) -> Result<u8, PackParseError> {
        self.need(1)?;
        let v = self.d[self.p];
        self.p += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], PackParseError> {
        self.need(n)?;
        let s = &self.d[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u32_be(&mut self) -> Result<u32, PackParseError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

/// 读取对象头大小变长整数（小端 7-bit 组，MSB 续位）。
fn read_size(c: &mut Cur, first: u8) -> u64 {
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut b = first;
    while b & 0x80 != 0 {
        b = c.d[c.p];
        c.p += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    size
}

/// ofs-delta 的负距离编码。
fn read_ofs(c: &mut Cur, first: u8) -> Result<u64, PackParseError> {
    let mut ofs = (first & 0x7f) as u64;
    let mut b = first;
    while b & 0x80 != 0 {
        b = c.u8()?;
        ofs = ofs.wrapping_add(1).wrapping_shl(7) | (b & 0x7f) as u64;
    }
    Ok(ofs)
}

struct Inflated {
    payload: Vec<u8>,
    consumed: usize,
    actual_len: u64,
}

/// 从 `d[pos..]` 解压**恰好一个** zlib 流，返回消费的压缩字节数。
///
/// - 不信任 declared：实际长度以解压器为准；
/// - 输出一旦超过 declared，仅保留前 [`SPOOF_EVIDENCE_CAP`] 字节做证据，
///   但继续解压以确定 zlib 边界，从而隔离坏对象后继续扫描后续对象；
/// - 实际长度超过 `hard_cap` 时放弃（无法安全定位炸弹边界）。
fn inflate_one(
    d: &[u8],
    pos: usize,
    declared: u64,
    hard_cap: usize,
) -> Result<Inflated, ParseOutcome> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut total_in: u64 = 0;
    let hard = hard_cap as u64;
    // 合法对象全量保留；声明大小异常大时按硬上限渐进分配，绝不让声明值驱动分配。
    let initial = (declared.min(64 * 1024) as usize).max(1024);
    let mut cap = initial.min(1 << 20).max(1024);
    loop {
        let in_before = dec.total_in();
        let out_before = dec.total_out();
        if (cap as u64) <= out_before {
            cap = (cap * 2).min((hard as usize).saturating_add(1).min(1 << 28));
        }
        if out.capacity() < cap {
            out.reserve(cap - out.len());
        }
        out.resize(cap, 0);
        let ret = dec.decompress(
            &d[(pos + total_in as usize)..],
            &mut out[(out_before as usize)..],
            FlushDecompress::None,
        );
        let produced = dec.total_out() - out_before;
        let consumed = dec.total_in() - in_before;
        total_in += consumed;
        let actual = dec.total_out();

        if actual > hard {
            return Err(ParseOutcome::TooLarge { actual, cap: hard });
        }
        // 大小欺骗：不再继续保留负载（只留证据前缀），但仍要跑到流结束找边界。
        if actual > declared {
            out.truncate(SPOOF_EVIDENCE_CAP.min(actual as usize));
        } else {
            out.truncate(actual as usize);
        }

        match ret {
            Ok(Status::StreamEnd) => {
                return Ok(Inflated {
                    payload: out,
                    consumed: total_in as usize,
                    actual_len: actual,
                });
            }
            Ok(Status::Ok) => {
                // 需要更多输入才能继续，而输入已耗尽 => 截断。
                if (pos + total_in as usize) >= d.len() {
                    return Err(ParseOutcome::TruncatedZlib);
                }
            }
            Err(_) if actual > hard => return Err(ParseOutcome::TooLarge { actual, cap: hard }),
            Err(e) => return Err(ParseOutcome::ZlibCorrupt { message: e.to_string() }),
            Ok(Status::BufError) => return Err(ParseOutcome::ZlibCorrupt {
                message: "decompressor buffer error".into(),
            }),
        }
    }
}

pub fn parse_pack(data: &[u8]) -> Result<PackFile, PackParseError> {
    let mut c = Cur { d: data, p: 0 };
    if c.take(4)? != b"PACK" {
        return Err(PackParseError::BadMagic { at: 0 });
    }
    let version = c.u32_be()?;
    if version != 2 {
        return Err(PackParseError::UnsupportedVersion { version });
    }
    let count = c.u32_be()?;

    let mut entries: Vec<PackEntry> = Vec::with_capacity(count.min(100_000) as usize);

    for _ in 0..count {
        let offset = c.p as u64;
        let first = c.u8()?;
        let kind_bits = (first >> 4) & 0x07;
        let kind = PackEntryKind::from_bits(kind_bits)
            .ok_or(PackParseError::BadTypeBits { offset, bits: kind_bits })?;
        let declared = read_size(&mut c, first);
        let mut ofs_negative = None;
        let mut ref_base = None;
        if kind == PackEntryKind::OfsDelta {
            let fb = c.u8()?;
            let neg = read_ofs(&mut c, fb)?;
            let base = offset as i64 - neg as i64;
            if base < 0 || base >= offset as i64 {
                return Err(PackParseError::OfsOutOfPack { offset, base });
            }
            ofs_negative = Some(neg);
        } else if kind == PackEntryKind::RefDelta {
            let s = c.take(20)?;
            ref_base = Some(Oid::from_slice(s));
        }
        let data_offset = c.p as u64;

        let mut crc = crc32fast::Hasher::new();
        crc.update(&data[offset as usize..c.p]);

        let infl = match inflate_one(data, c.p, declared, crate::HARD_INFLATE_CAP) {
            Ok(v) => v,
            Err(outcome @ (ParseOutcome::ZlibCorrupt { .. } | ParseOutcome::TruncatedZlib)) => {
                return Err(match outcome {
                    ParseOutcome::ZlibCorrupt { message } => {
                        PackParseError::ZlibFatal { offset, message }
                    }
                    _ => PackParseError::Truncated { at: c.p, need: 1, have: 0 },
                });
            }
            Err(ParseOutcome::TooLarge { actual, cap }) => {
                return Err(PackParseError::InflateTooLarge { offset, actual, cap });
            }
            Err(_) => unreachable!(),
        };
        let comp_bytes = &data[c.p..c.p + infl.consumed];
        crc.update(comp_bytes);
        let crc32 = crc.finalize();
        c.p += infl.consumed;

        let outcome = if infl.actual_len == declared {
            ParseOutcome::Ok
        } else {
            ParseOutcome::SizeSpoof { declared, actual: infl.actual_len }
        };
        entries.push(PackEntry {
            offset,
            data_offset,
            declared_size: declared,
            kind,
            ofs_negative,
            ref_base,
            payload: infl.payload,
            crc32,
            entry_len: c.p as u64 - offset,
            outcome,
            next_offset: c.p as u64,
        });
    }

    let trailer_offset = c.p as u64;
    let tr = c.take(20).map_err(|_| PackParseError::TrailerMissing { at: c.p })?;
    let trailer = Oid::from_slice(tr);
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(&data[..trailer_offset as usize]);
    let want = Oid(h.finalize().into());
    let trailer_ok = want == trailer;
    let trailing_garbage = data.len() - c.p;

    Ok(PackFile {
        version,
        count,
        entries,
        trailer,
        trailer_offset,
        trailer_ok,
        trailing_garbage,
    })
}
