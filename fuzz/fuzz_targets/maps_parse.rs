#![no_main]
use libfuzzer_sys::fuzz_target;
use wraith::maps::MemoryMap;

// Property: parsing arbitrary text never panics, regions come out sorted by start
// address, and lookups/formatting on whatever was parsed never panic.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let map = MemoryMap::parse(&text);
    assert!(map.regions().windows(2).all(|w| w[0].start <= w[1].start));
    for r in map.regions() {
        let _ = r.to_string();
        let _ = map.region_at(r.start);
        let _ = map.region_at(r.end);
    }
    let _ = map.region_at(0);
    let _ = map.region_at(u64::MAX);
});
