//! A deliberately ordinary program. It performs a spread of everyday syscalls —
//! including sensitive ones like `socket` — but always from legitimate,
//! file-backed code. Wraith must report it as clean. Used by the test-suite as
//! the false-positive control and handy for a live "nothing fires" demo.

use std::io::Read;

fn main() {
    println!("benign: starting normal work");

    // Filesystem: open + read a file (open/read/close from libc — legit code).
    if let Ok(mut f) = std::fs::File::open("/proc/self/status") {
        let mut buf = String::new();
        let _ = f.read_to_string(&mut buf);
        println!("benign: read {} bytes from /proc/self/status", buf.len());
    }

    // Network: create and immediately close a socket. `socket` is a sensitive
    // syscall, but issued from legitimate code, so it must NOT be flagged
    // unless the operator explicitly asks for --audit-sensitive.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd >= 0 {
            libc::close(fd);
            println!("benign: opened and closed a socket from legitimate code");
        }
    }

    // A little compute so the process lives long enough to be worth tracing.
    let mut acc: u64 = 0;
    for i in 0..100_000u64 {
        acc = acc.wrapping_add(i.wrapping_mul(2654435761));
    }
    println!("benign: done ({acc:#x})");
}
