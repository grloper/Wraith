//! A compact x86-64 syscall-number table, limited to the calls that matter for
//! post-exploitation behaviour plus the memory-management calls we must track
//! to keep the memory map fresh. Unknown numbers render as `syscall_<n>`.

use std::borrow::Cow;

/// The syscalls an attacker reaches for after gaining control: spawning
/// programs, touching the filesystem, opening the network, changing identity,
/// tampering with other processes, or disabling the kernel's own defences.
/// Emitting these from a foreign origin is the difference between "something is
/// odd" and "you are being popped".
///
/// Membership only ever *raises* the stakes of a call already coming from
/// injected code (or surfaces an INFO breadcrumb under `--audit-sensitive`); a
/// legitimate program issuing any of these from its own `.text` is still
/// silent, so the set can be generous without manufacturing false positives.
pub const SENSITIVE: &[u64] = &[
    // Code execution / launching new programs.
    59,  // execve
    322, // execveat
    319, // memfd_create — fileless payloads: an anonymous file run via /proc/self/fd
    // Network: opening channels or exfiltrating data.
    41,  // socket
    42,  // connect
    49,  // bind
    50,  // listen
    43,  // accept
    288, // accept4
    44,  // sendto — data exfiltration
    46,  // sendmsg
    307, // sendmmsg
    // Filesystem access from injected code.
    2,   // open
    257, // openat
    // Identity / privilege changes.
    105, // setuid
    106, // setgid
    117, // setresuid
    161, // chroot
    // Reaching into other processes.
    101, // ptrace
    310, // process_vm_readv — cross-process memory read
    311, // process_vm_writev — cross-process injection without ptrace
    438, // pidfd_getfd — steal a file descriptor from another process
    // Spawning execution contexts.
    56,  // clone
    57,  // fork
    58,  // vfork
    // Disabling kernel defences / escaping containers.
    157, // prctl — can clear NO_NEW_PRIVS, rename, disable core dumps, etc.
    317, // seccomp
    321, // bpf — loading eBPF programs
    323, // userfaultfd — kernel-exploit stabilisation / TOCTOU races
    165, // mount
    272, // unshare
    308, // setns — entering another namespace (container escape)
    // Reaching ring 0.
    175, // init_module
    313, // finit_module
    246, // kexec_load
    // io_uring can issue syscalls out of band of the ptrace/seccomp syscall path.
    425, // io_uring_setup
    426, // io_uring_enter
];

/// Memory-management syscalls after which the process memory map may have
/// changed and must be re-read.
pub const MEMORY_OPS: &[u64] = &[
    9,   // mmap
    10,  // mprotect
    11,  // munmap
    25,  // mremap
    12,  // brk
    26,  // msync
];

pub fn is_sensitive(nr: u64) -> bool {
    SENSITIVE.contains(&nr)
}

pub fn is_memory_op(nr: u64) -> bool {
    MEMORY_OPS.contains(&nr)
}

pub fn is_mprotect(nr: u64) -> bool {
    nr == 10
}

pub fn is_mmap(nr: u64) -> bool {
    nr == 9
}

pub fn is_execve(nr: u64) -> bool {
    nr == 59 || nr == 322
}

pub fn is_network_input(nr: u64) -> bool {
    // read(0), recvfrom(45), recvmsg(47), readv(19), recvmmsg(299) — the usual
    // channels an exploit's first-stage payload arrives on.
    matches!(nr, 0 | 45 | 47 | 19 | 299)
}

/// Human-readable name for a syscall number, or `syscall_<n>` if unknown.
///
/// Returns a [`Cow`] so the overwhelmingly common case — a syscall we know —
/// borrows a `&'static str` and allocates nothing on the hot path; only an
/// unknown number pays for the `syscall_<n>` formatting.
pub fn name(nr: u64) -> Cow<'static, str> {
    let s = match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        19 => "readv",
        25 => "mremap",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        49 => "bind",
        50 => "listen",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        101 => "ptrace",
        105 => "setuid",
        106 => "setgid",
        117 => "setresuid",
        157 => "prctl",
        161 => "chroot",
        165 => "mount",
        175 => "init_module",
        231 => "exit_group",
        246 => "kexec_load",
        257 => "openat",
        272 => "unshare",
        288 => "accept4",
        299 => "recvmmsg",
        307 => "sendmmsg",
        308 => "setns",
        310 => "process_vm_readv",
        311 => "process_vm_writev",
        313 => "finit_module",
        317 => "seccomp",
        319 => "memfd_create",
        321 => "bpf",
        322 => "execveat",
        323 => "userfaultfd",
        425 => "io_uring_setup",
        426 => "io_uring_enter",
        438 => "pidfd_getfd",
        _ => return Cow::Owned(format!("syscall_{nr}")),
    };
    Cow::Borrowed(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_known_and_unknown() {
        assert_eq!(&*name(59), "execve");
        assert_eq!(&*name(10), "mprotect");
        assert_eq!(&*name(9999), "syscall_9999");
        // Known syscalls borrow a static string; only unknowns allocate.
        assert!(matches!(name(59), Cow::Borrowed(_)));
        assert!(matches!(name(9999), Cow::Owned(_)));
    }

    #[test]
    fn category_predicates() {
        assert!(is_sensitive(59));
        assert!(is_execve(322));
        assert!(is_memory_op(10));
        assert!(is_mprotect(10));
        assert!(is_network_input(0));
        assert!(!is_sensitive(1)); // write is not, by itself, sensitive
    }

    #[test]
    fn modern_evasion_syscalls_are_sensitive() {
        // The additions that cover fileless, cross-process, defence-evasion and
        // container-escape techniques must all be in the sensitive set, and each
        // must render with a real name rather than `syscall_<n>`.
        for nr in [
            319, // memfd_create
            311, // process_vm_writev
            321, // bpf
            317, // seccomp
            323, // userfaultfd
            308, // setns
            426, // io_uring_enter
            44,  // sendto
        ] {
            assert!(is_sensitive(nr), "syscall {nr} should be sensitive");
            assert!(!name(nr).starts_with("syscall_"), "syscall {nr} needs a name");
        }
    }

    #[test]
    fn recvmmsg_is_network_input() {
        assert!(is_network_input(299));
    }
}
