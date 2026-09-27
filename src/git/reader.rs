//! 大端游标读取器，所有读取都做边界检查，越界返回 `std::io::Error`(UnexpectedEof)。

use std::io;

pub struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("need {} bytes at {}, have {}", n, self.pos, self.remaining()),
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> io::Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn u64(&mut self) -> io::Result<u64> {
        let s = self.take(8)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub fn bytes20(&mut self) -> io::Result<[u8; 20]> {
        let s = self.take(20)?;
        let mut o = [0u8; 20];
        o.copy_from_slice(s);
        Ok(o)
    }

    /// pack 风格的变长小端整数（MSB=延续位）。
    pub fn size_encoding(&mut self) -> io::Result<u64> {
        let mut shift = 0u32;
        let mut value = 0u64;
        loop {
            let b = self.u8()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "size encoding too long"));
            }
        }
        Ok(value)
    }

    /// ofs-delta 的负偏移编码（每个后续字节带 c=0x80 再加 1）。
    pub fn ofs_delta_distance(&mut self) -> io::Result<u64> {
        let mut c = self.u8()?;
        let mut value = u64::from(c & 0x7f);
        while c & 0x80 != 0 {
            c = self.u8()?;
            value = value
                .checked_add(1)
                .and_then(|v| v.checked_shl(7))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ofs distance overflow"))?;
            value |= u64::from(c & 0x7f);
        }
        Ok(value)
    }
}
