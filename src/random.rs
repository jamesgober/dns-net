//! Random query ids, source ports, and case bits, from the operating
//! system's random source (mod-rand's third tier: `getrandom` on Linux,
//! `getentropy` on macOS, `ProcessPrng` on Windows).
//!
//! The bytes are drawn 256 at a time, so a query costs one system call in
//! about seven. A failing source fails the query: there is no fallback to a
//! predictable generator.

use std::io;

const BATCH: usize = 256;

/// Owned by the resolver's thread.
pub(crate) struct Random {
    buf: [u8; BATCH],
    at: usize,
}

impl Random {
    pub(crate) fn new() -> Random {
        Random {
            buf: [0; BATCH],
            at: BATCH,
        }
    }

    /// Fills `out` (at most [`BATCH`] bytes).
    pub(crate) fn fill(&mut self, out: &mut [u8]) -> io::Result<()> {
        debug_assert!(out.len() <= BATCH);
        if BATCH - self.at < out.len() {
            mod_rand::tier3::fill_bytes(&mut self.buf)?;
            self.at = 0;
        }
        out.copy_from_slice(&self.buf[self.at..self.at + out.len()]);
        // Bytes handed out are not kept.
        self.buf[self.at..self.at + out.len()].fill(0);
        self.at += out.len();
        Ok(())
    }

    pub(crate) fn u16(&mut self) -> io::Result<u16> {
        let mut b = [0; 2];
        self.fill(&mut b)?;
        Ok(u16::from_ne_bytes(b))
    }

    /// Uniform in `0..n` (`n > 0`), by rejection so no value is favoured.
    pub(crate) fn below(&mut self, n: u32) -> io::Result<u32> {
        let zone = u32::MAX - (u32::MAX % n);
        loop {
            let mut b = [0; 4];
            self.fill(&mut b)?;
            let v = u32::from_ne_bytes(b);
            if v < zone {
                return Ok(v % n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_vary_and_stay_in_range() {
        let mut r = Random::new();
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| r.u16().unwrap()).collect();
        assert!(ids.len() > 60, "{} distinct of 64", ids.len());
        for _ in 0..1000 {
            assert!(r.below(7).unwrap() < 7);
        }
        let mut big = [0u8; 200];
        r.fill(&mut big).unwrap();
        r.fill(&mut big).unwrap();
        assert!(big.iter().any(|&b| b != 0));
    }
}
