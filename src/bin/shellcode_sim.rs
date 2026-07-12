//! A self-contained exploitation *simulator* — no real vulnerability, no
//! external target. It reproduces the observable tail end of virtually every
//! memory-corruption exploit: allocate an executable page, write a payload
//! into it, and transfer control there so a syscall is issued from injected
//! code. This is the behaviour Wraith exists to catch, and it lets the
//! test-suite prove detection without shipping a real exploit.
//!
//! The payload is a hand-assembled x86-64 stub that performs `socket(2,1,0)`
//! (a sensitive syscall) and returns cleanly:
//!
//! ```text
//!   bf 02 00 00 00    mov  edi, 2        ; AF_INET
//!   be 01 00 00 00    mov  esi, 1        ; SOCK_STREAM
//!   31 d2             xor  edx, edx      ; protocol 0
//!   b8 29 00 00 00    mov  eax, 41       ; __NR_socket
//!   0f 05             syscall
//!   c3                ret
//! ```

use std::ptr;

#[cfg(target_arch = "x86_64")]
const PAYLOAD: [u8; 19] = [
    0xbf, 0x02, 0x00, 0x00, 0x00, // mov edi, 2
    0xbe, 0x01, 0x00, 0x00, 0x00, // mov esi, 1
    0x31, 0xd2, // xor edx, edx
    0xb8, 0x29, 0x00, 0x00, 0x00, // mov eax, 41 (socket)
    0x0f, 0x05, // syscall  <-- issued from the RWX page
    // NOTE: `ret` (0xc3) is appended at runtime; keeping the array at the
    // instruction boundary above documents the syscall site clearly.
];

#[cfg(target_arch = "x86_64")]
fn main() {
    const PAGE: usize = 4096;

    // Stage 1: allocate a writable+executable page (W^X violation) — exactly
    // what a payload does to hold its shellcode.
    let mem = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(mem != libc::MAP_FAILED, "mmap RWX failed");
    println!("shellcode-sim: staged RWX page at {mem:p}");

    // Stage 2: write the payload plus a trailing `ret`.
    unsafe {
        ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), mem as *mut u8, PAYLOAD.len());
        *(mem as *mut u8).add(PAYLOAD.len()) = 0xc3; // ret
    }

    // Stage 3: transfer control into the injected code. The `syscall` executes
    // with RIP inside the RWX page — the provenance violation Wraith detects.
    let entry: extern "C" fn() -> i64 = unsafe { std::mem::transmute(mem) };
    let fd = entry();
    println!("shellcode-sim: payload ran from injected page; socket() -> {fd}");

    if fd >= 0 {
        unsafe { libc::close(fd as libc::c_int) };
    }
    unsafe { libc::munmap(mem, PAGE) };
    println!("shellcode-sim: done");
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!("shellcode-sim: this demonstrator is x86-64 only");
    std::process::exit(1);
}
