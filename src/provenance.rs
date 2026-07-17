//! Syscall provenance classification.
//!
//! Given the instruction pointer of a stopped tracee and its current memory
//! map, decide where the syscall *came from*. Benign programs only ever issue
//! syscalls from file-backed executable pages (their own `.text`, a shared
//! library, or the kernel vDSO). Everything else is, to varying degrees, the
//! fingerprint of code that was injected or reached through corrupted control
//! flow.

use crate::maps::{MemoryMap, RegionKind};

/// Where a syscall instruction was executing from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// File-backed executable page — the program's own code or a library.
    LegitCode,
    /// Kernel vDSO fast-syscall page.
    Vdso,
    /// Executing from a writable+executable page (W^X violated in place).
    WxViolation,
    /// Executing from the thread stack — textbook injected shellcode.
    StackExec,
    /// Executing from the heap — textbook injected shellcode.
    HeapExec,
    /// Executing from an anonymous executable page (JIT payload or staged
    /// shellcode). Legitimate for JIT engines, hence its own bucket.
    AnonExec,
    /// The instruction pointer is not inside any mapped region.
    Unmapped,
    /// The containing page is not marked executable. Should be impossible for
    /// a live syscall; indicates a stale map or an exotic state.
    NonExec,
}

impl Origin {
    /// True for origins that never occur during legitimate execution.
    pub fn is_anomalous(self) -> bool {
        !matches!(self, Origin::LegitCode | Origin::Vdso)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Origin::LegitCode => "legit-code",
            Origin::Vdso => "vdso",
            Origin::WxViolation => "wx-violation",
            Origin::StackExec => "stack-exec",
            Origin::HeapExec => "heap-exec",
            Origin::AnonExec => "anon-exec",
            Origin::Unmapped => "unmapped",
            Origin::NonExec => "non-exec",
        }
    }
}

/// Classify the origin of the instruction at `rip` against `map`.
pub fn classify_rip(map: &MemoryMap, rip: u64) -> Origin {
    let Some(region) = map.region_at(rip) else {
        return Origin::Unmapped;
    };

    if matches!(region.kind, RegionKind::Kernel) {
        return Origin::Vdso;
    }

    if !region.exec {
        return Origin::NonExec;
    }

    // From here down the page is executable; the question is whether it *should*
    // be. Precedence matters: a writable+executable page is the strongest
    // signal, so it wins even over the stack/heap labels.
    if region.write {
        return Origin::WxViolation;
    }

    match region.kind {
        RegionKind::Stack => Origin::StackExec,
        RegionKind::Heap => Origin::HeapExec,
        RegionKind::File(_) => Origin::LegitCode,
        RegionKind::Anonymous => Origin::AnonExec,
        RegionKind::Kernel => Origin::Vdso, // handled above; here for exhaustiveness
    }
}

/// Result of inspecting the stack pointer at syscall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackState {
    /// Stack pointer sits in a normal writable stack/anonymous region.
    Normal,
    /// Stack pointer sits in the heap — a classic ROP stack pivot target.
    PivotedToHeap,
    /// Stack pointer sits in a file-backed region — an impossible place for a
    /// real stack, so almost certainly a pivot into attacker-chosen data.
    PivotedToFile,
    /// Stack pointer is not in any mapped region.
    Unmapped,
}

impl StackState {
    pub fn is_anomalous(self) -> bool {
        !matches!(self, StackState::Normal)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            StackState::Normal => "normal",
            StackState::PivotedToHeap => "pivot-heap",
            StackState::PivotedToFile => "pivot-file",
            StackState::Unmapped => "unmapped",
        }
    }
}

/// Inspect the stack pointer for evidence of a ROP stack pivot.
///
/// This is a heuristic: multi-threaded programs place thread stacks in
/// anonymous mappings, which we accept as normal. What no legitimate program
/// does is run with its stack pointer inside the heap or inside a file-backed
/// image, so those are the states we flag.
pub fn classify_rsp(map: &MemoryMap, rsp: u64) -> StackState {
    let Some(region) = map.region_at(rsp) else {
        return StackState::Unmapped;
    };
    match &region.kind {
        RegionKind::Heap => StackState::PivotedToHeap,
        RegionKind::File(_) => StackState::PivotedToFile,
        _ => StackState::Normal,
    }
}

/// Decode the `prot` argument of an `mmap`/`mprotect` syscall into the
/// dangerous combinations Wraith cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prot {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Prot {
    pub fn from_raw(prot: u64) -> Self {
        Prot {
            read: prot & libc::PROT_READ as u64 != 0,
            write: prot & libc::PROT_WRITE as u64 != 0,
            exec: prot & libc::PROT_EXEC as u64 != 0,
        }
    }

    /// A page requested writable *and* executable at once.
    pub fn is_wx(self) -> bool {
        self.write && self.exec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = "\
55f000001000-55f000002000 r-xp 00000000 08:01 1 /usr/bin/app
55f000003000-55f000010000 rw-p 00000000 00:00 0 [heap]
7f0000000000-7f0000021000 r-xp 00000000 08:01 2 /usr/lib/libc.so.6
7f0000030000-7f0000031000 rwxp 00000000 00:00 0
7f0000040000-7f0000041000 r-xp 00000000 00:00 0
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]
7ffd00100000-7ffd00104000 r-xp 00000000 00:00 0 [vdso]";

    fn m() -> MemoryMap {
        MemoryMap::parse(MAP)
    }

    #[test]
    fn legit_code_from_binary_and_libc() {
        assert_eq!(classify_rip(&m(), 0x55f000001500), Origin::LegitCode);
        assert_eq!(classify_rip(&m(), 0x7f0000000500), Origin::LegitCode);
    }

    #[test]
    fn vdso_is_legit() {
        assert_eq!(classify_rip(&m(), 0x7ffd00100010), Origin::Vdso);
        assert!(!classify_rip(&m(), 0x7ffd00100010).is_anomalous());
    }

    #[test]
    fn rwx_page_is_wx_violation() {
        let o = classify_rip(&m(), 0x7f0000030010);
        assert_eq!(o, Origin::WxViolation);
        assert!(o.is_anomalous());
    }

    #[test]
    fn anon_exec_page_is_flagged_but_distinct() {
        let o = classify_rip(&m(), 0x7f0000040010);
        assert_eq!(o, Origin::AnonExec);
        assert!(o.is_anomalous());
    }

    #[test]
    fn unmapped_rip() {
        assert_eq!(classify_rip(&m(), 0xdead0000), Origin::Unmapped);
    }

    #[test]
    fn non_exec_page() {
        // Executing a syscall from the (non-exec) heap page.
        assert_eq!(classify_rip(&m(), 0x55f000003100), Origin::NonExec);
    }

    #[test]
    fn stack_pivot_into_heap() {
        assert_eq!(classify_rsp(&m(), 0x55f000004000), StackState::PivotedToHeap);
    }

    #[test]
    fn stack_pivot_into_file() {
        assert_eq!(classify_rsp(&m(), 0x7f0000000800), StackState::PivotedToFile);
    }

    #[test]
    fn normal_stack_pointer() {
        assert_eq!(classify_rsp(&m(), 0x7ffd00010000), StackState::Normal);
    }

    #[test]
    fn prot_decoding() {
        let p = Prot::from_raw((libc::PROT_WRITE | libc::PROT_EXEC) as u64);
        assert!(p.is_wx());
        let ro = Prot::from_raw(libc::PROT_READ as u64);
        assert!(!ro.is_wx());
    }
}
