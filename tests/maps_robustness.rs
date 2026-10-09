//! Deterministic property-style robustness tests for the `/proc/<pid>/maps`
//! parser (no external dependencies). A coverage-guided target lives in `fuzz/`.

use wraith::maps::{MemoryMap, RegionKind};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[(self.next() % xs.len() as u64) as usize]
    }
}

fn check_invariants(map: &MemoryMap) {
    assert!(map.regions().windows(2).all(|w| w[0].start <= w[1].start));
    assert_eq!(map.is_empty(), map.regions().is_empty());
    for r in map.regions() {
        let _ = r.to_string();
        let _ = r.label();
        let _ = map.region_at(r.start);
        let _ = map.region_at(r.end);
    }
    let _ = map.region_at(0);
    let _ = map.region_at(u64::MAX);
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for _ in 0..3000 {
        let len = (rng.next() % 300) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        check_invariants(&MemoryMap::parse(&String::from_utf8_lossy(&bytes)));
    }
}

#[test]
fn mutated_valid_lines_never_panic() {
    let pieces = [
        "7f0000000000-7f0000001000",
        "ffffffffffffffff-ffffffffffffffff",
        "0-0",
        "-",
        "rwxp",
        "r-xp",
        "rwxs",
        "xx",
        "00000000",
        "00:00",
        "103:02",
        "0",
        "123456",
        "/usr/lib/libc.so.6",
        "[stack]",
        "[heap]",
        "[vdso]",
        "[vvar]",
        "[vsyscall]",
        "/tmp/a b (deleted)",
        "\u{fffd}",
        "",
    ];
    let mut rng = Rng(0xDEADBEEFCAFEF00D);
    for _ in 0..5000 {
        let mut text = String::new();
        for _ in 0..(1 + rng.next() % 6) {
            for _ in 0..(rng.next() % 7) {
                text.push_str(rng.pick(&pieces));
                text.push(if rng.next() % 5 == 0 { '\t' } else { ' ' });
            }
            text.push('\n');
        }
        check_invariants(&MemoryMap::parse(&text));
    }
}

#[test]
fn well_formed_map_is_parsed_and_sorted() {
    // Deliberately out of order: parse() must sort so region_at stays correct.
    let raw = "\
7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0                          [stack]\n\
55d000000000-55d000001000 r-xp 00000000 08:01 1234                       /usr/bin/true\n\
7f0000000000-7f0000001000 rwxp 00000000 00:00 0\n";
    let map = MemoryMap::parse(raw);
    assert_eq!(map.regions().len(), 3);
    check_invariants(&map);
    let stack = map.region_at(0x7ffc00000800).expect("stack region");
    assert_eq!(stack.kind, RegionKind::Stack);
    let anon = map.region_at(0x7f0000000010).expect("anon region");
    assert_eq!(anon.kind, RegionKind::Anonymous);
    assert!(anon.write && anon.exec);
    assert!(map.region_at(0x7f0000001000).is_none());
}
