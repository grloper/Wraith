# Fuzzing

Requires nightly Rust and `cargo install cargo-fuzz`.

    cargo +nightly fuzz run maps_parse -- -max_total_time=60

Deterministic dependency-free property tests for the same parser run in normal CI
(`tests/maps_robustness.rs`).
