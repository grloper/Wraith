//! A benign *multithreaded* target — the false-positive control for Wraith's
//! thread-following. Several worker threads run concurrently, each issuing a
//! stream of ordinary syscalls (writes, allocations, sleeps) from legitimate
//! code. Wraith follows every one of them and must stay completely silent:
//! spawning threads is not exploitation.

use std::thread;
use std::time::Duration;

fn work(id: usize) -> u64 {
    // A little CPU work plus routine I/O — the kind of syscall traffic a real
    // worker thread produces, all from legitimate file-backed code.
    let mut acc = id as u64;
    for i in 0..5 {
        acc = acc.wrapping_mul(2654435761).wrapping_add(i);
        // `write` and `nanosleep` from libc are legitimate-origin syscalls.
        println!("worker {id}: tick {i} acc={acc:#x}");
        thread::sleep(Duration::from_millis(2));
    }
    acc
}

fn main() {
    let handles: Vec<_> = (0..4).map(|id| thread::spawn(move || work(id))).collect();

    let mut total = 0u64;
    for h in handles {
        total = total.wrapping_add(h.join().expect("worker thread panicked"));
    }

    println!("benign-threads: done (total={total:#x})");
}
