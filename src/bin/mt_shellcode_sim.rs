//! A self-contained exploitation simulator whose payload fires from a *worker
//! thread*, not the main thread. It is identical in spirit to `shellcode-sim`
//! — stage an RWX page, write a payload, execute a syscall from it — but the
//! whole sequence happens inside a `std::thread`, the way an exploit against a
//! threaded daemon (a request handler, a parser worker) actually plays out.
//!
//! A tracer that only watches the main thread sees nothing here; the RWX
//! staging and the injected `socket(2,1,0)` both occur on a thread born from a
//! `clone`. Catching it is the whole point of Wraith's thread-following, so
//! this target is the positive control for that capability.
//!
//! The payload is the same hand-assembled x86-64 stub as `shellcode-sim`:
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
use std::thread;

#[cfg(target_arch = "x86_64")]
const PAYLOAD: [u8; 19] = [
    0xbf, 0x02, 0x00, 0x00, 0x00, // mov edi, 2
    0xbe, 0x01, 0x00, 0x00, 0x00, // mov esi, 1
    0x31, 0xd2, // xor edx, edx
    0xb8, 0x29, 0x00, 0x00, 0x00, // mov eax, 41 (socket)
    0x0f, 0x05, // syscall  <-- issued from the RWX page, on a worker thread
];

#[cfg(target_arch = "x86_64")]
fn detonate() {
    const PAGE: usize = 4096;

    // Stage 1: allocate a writable+executable page (W^X violation).
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
    println!("mt-shellcode-sim: worker staged RWX page at {mem:p}");

    // Stage 2: write the payload plus a trailing `ret`.
    unsafe {
        ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), mem as *mut u8, PAYLOAD.len());
        *(mem as *mut u8).add(PAYLOAD.len()) = 0xc3; // ret
    }

    // Stage 3: transfer control into the injected code. The `syscall` executes
    // with RIP inside the RWX page — on a thread the tracer only sees if it
    // followed the `clone`.
    let entry: extern "C" fn() -> i64 = unsafe { std::mem::transmute(mem) };
    let fd = entry();
    println!("mt-shellcode-sim: injected socket() from worker thread -> {fd}");

    if fd >= 0 {
        unsafe { libc::close(fd as libc::c_int) };
    }
    unsafe { libc::munmap(mem, PAGE) };
}

#[cfg(target_arch = "x86_64")]
fn main() {
    // The main thread does nothing exploitative; the payload lives on a worker.
    let worker = thread::spawn(detonate);
    worker.join().expect("worker thread panicked");
    println!("mt-shellcode-sim: done");
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!("mt-shellcode-sim: this demonstrator is x86-64 only");
    std::process::exit(1);
}
