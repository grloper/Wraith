//! Parser for `/proc/<pid>/maps`.
//!
//! The virtual-memory map is the ground truth Wraith uses to attribute a
//! syscall to the memory region its instruction pointer sits in. We only
//! re-read the map when a memory-management syscall (`mmap`/`mprotect`/
//! `munmap`) could have changed it, or on a cache miss, so parsing stays off
//! the hot path.

use std::fmt;
use std::fs;
use std::io;

/// The logical kind of a mapped region, derived from its pathname column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionKind {
    /// The main thread stack (`[stack]`).
    Stack,
    /// The program break heap (`[heap]`).
    Heap,
    /// Kernel-provided fast-syscall page (`[vdso]`/`[vvar]`/`[vsyscall]`).
    Kernel,
    /// Backed by a file on disk (executable image, shared library, mmap'd file).
    File(String),
    /// Anonymous mapping with no backing file and no special name.
    Anonymous,
}

/// A single line of the process memory map.
#[derive(Debug, Clone)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub shared: bool,
    pub kind: RegionKind,
}

impl Region {
    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// True when the region is backed by a real file on disk. File-backed
    /// executable pages are the *only* legitimate origin for program code.
    pub fn is_file_backed(&self) -> bool {
        matches!(self.kind, RegionKind::File(_))
    }

    /// A short, human-readable label for reports.
    pub fn label(&self) -> String {
        match &self.kind {
            RegionKind::Stack => "[stack]".into(),
            RegionKind::Heap => "[heap]".into(),
            RegionKind::Kernel => "[kernel]".into(),
            RegionKind::Anonymous => "anon".into(),
            RegionKind::File(p) => {
                // Just the basename keeps event lines readable.
                p.rsplit('/').next().unwrap_or(p).to_string()
            }
        }
    }

    fn perms(&self) -> String {
        format!(
            "{}{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.exec { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' },
        )
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x}-{:#x} {} {}",
            self.start,
            self.end,
            self.perms(),
            self.label()
        )
    }
}

/// An ordered snapshot of a process's virtual address space.
#[derive(Debug, Clone, Default)]
pub struct MemoryMap {
    regions: Vec<Region>,
}

impl MemoryMap {
    /// Read and parse `/proc/<pid>/maps`.
    pub fn read(pid: i32) -> io::Result<Self> {
        let raw = fs::read_to_string(format!("/proc/{pid}/maps"))?;
        Ok(Self::parse(&raw))
    }

    /// Parse the textual maps format. Malformed lines are skipped rather than
    /// aborting the trace, since a single unexpected line should never blind
    /// the detector.
    pub fn parse(raw: &str) -> Self {
        let regions = raw.lines().filter_map(parse_line).collect();
        Self { regions }
    }

    /// The region containing `addr`, if any. Regions never overlap, so the
    /// first hit is the answer.
    pub fn region_at(&self, addr: u64) -> Option<&Region> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}

fn parse_perms(field: &str) -> Option<(bool, bool, bool, bool)> {
    let b = field.as_bytes();
    if b.len() < 4 {
        return None;
    }
    Some((
        b[0] == b'r',
        b[1] == b'w',
        b[2] == b'x',
        b[3] == b's',
    ))
}

fn classify(path: &str) -> RegionKind {
    match path {
        "" => RegionKind::Anonymous,
        "[stack]" => RegionKind::Stack,
        "[heap]" => RegionKind::Heap,
        "[vdso]" | "[vvar]" | "[vsyscall]" | "[vvar_vclock]" => RegionKind::Kernel,
        // Per-thread stacks appear as `[stack:tid]` on older kernels.
        p if p.starts_with("[stack") => RegionKind::Stack,
        // Any other bracketed pseudo-file is kernel-managed.
        p if p.starts_with('[') => RegionKind::Kernel,
        p => RegionKind::File(p.to_string()),
    }
}

fn parse_line(line: &str) -> Option<Region> {
    // Format: START-END PERMS OFFSET DEV INODE [PATHNAME]
    let mut it = line.split_whitespace();
    let range = it.next()?;
    let perms = it.next()?;
    let _offset = it.next()?;
    let _dev = it.next()?;
    let _inode = it.next()?;
    // Pathname may contain spaces; take the remainder of the line.
    let path = line
        .splitn(6, char::is_whitespace)
        .nth(5)
        .map(str::trim)
        .unwrap_or("");

    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;
    let (read, write, exec, shared) = parse_perms(perms)?;

    Some(Region {
        start,
        end,
        read,
        write,
        exec,
        shared,
        kind: classify(path),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
55f0aa3b1000-55f0aa3b2000 r-xp 00001000 08:01 131march /usr/bin/target
55f0aa3d0000-55f0aa3f1000 rw-p 00000000 00:00 0          [heap]
7f2c9c000000-7f2c9c021000 r-xp 00000000 08:01 262147     /usr/lib/x86_64-linux-gnu/libc.so.6
7f2c9d000000-7f2c9d001000 rwxp 00000000 00:00 0
7ffde1200000-7ffde1221000 rw-p 00000000 00:00 0          [stack]
7ffde13a0000-7ffde13a4000 r-xp 00000000 00:00 0          [vdso]";

    #[test]
    fn parses_all_regions() {
        let m = MemoryMap::parse(SAMPLE);
        assert_eq!(m.regions().len(), 6);
    }

    #[test]
    fn classifies_kinds() {
        let m = MemoryMap::parse(SAMPLE);
        assert!(matches!(m.region_at(0x55f0aa3b1500).unwrap().kind, RegionKind::File(_)));
        assert_eq!(m.region_at(0x55f0aa3d0100).unwrap().kind, RegionKind::Heap);
        assert_eq!(m.region_at(0x7ffde1200500).unwrap().kind, RegionKind::Stack);
        assert_eq!(m.region_at(0x7ffde13a0100).unwrap().kind, RegionKind::Kernel);
    }

    #[test]
    fn detects_rwx_region() {
        let m = MemoryMap::parse(SAMPLE);
        let r = m.region_at(0x7f2c9d000500).unwrap();
        assert!(r.read && r.write && r.exec);
        assert_eq!(r.kind, RegionKind::Anonymous);
    }

    #[test]
    fn address_outside_any_region() {
        let m = MemoryMap::parse(SAMPLE);
        assert!(m.region_at(0x1000).is_none());
    }

    #[test]
    fn perms_display_roundtrip() {
        let m = MemoryMap::parse(SAMPLE);
        let libc = m.region_at(0x7f2c9c000100).unwrap();
        assert!(libc.exec && !libc.write);
        assert_eq!(libc.label(), "libc.so.6");
    }
}
