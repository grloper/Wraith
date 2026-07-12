//! A compact x86-64 syscall-number table, limited to the calls that matter for
//! post-exploitation behaviour plus the memory-management calls we must track
//! to keep the memory map fresh. Unknown numbers render as `syscall_<n>`.

/// The syscalls an attacker reaches for after gaining control: spawning
/// programs, touching the filesystem, opening the network, changing identity,
/// or tampering with other processes. Emitting these from a foreign origin is
/// the difference between "something is odd" and "you are being popped".
pub const SENSITIVE: &[u64] = &[
    59,  // execve
    322, // execveat
    41,  // socket
    42,  // connect
    49,  // bind
    50,  // listen
    43,  // accept
    2,   // open
    257, // openat
    105, // setuid
    106, // setgid
    117, // setresuid
    101, // ptrace
    56,  // clone
    57,  // fork
    58,  // vfork
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
    // read(0), recvfrom(45), recvmsg(47), readv(19) — the usual channels an
    // exploit's first-stage payload arrives on.
    matches!(nr, 0 | 45 | 47 | 19)
}

/// Human-readable name for a syscall number, or `syscall_<n>` if unknown.
pub fn name(nr: u64) -> String {
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
        45 => "recvfrom",
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
        231 => "exit_group",
        257 => "openat",
        322 => "execveat",
        _ => return format!("syscall_{nr}"),
    };
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_known_and_unknown() {
        assert_eq!(name(59), "execve");
        assert_eq!(name(10), "mprotect");
        assert_eq!(name(9999), "syscall_9999");
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
}
