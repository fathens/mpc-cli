pub fn time<A>(f: impl FnOnce() -> A) -> (A, std::time::Duration) {
    let start = std::time::Instant::now();
    let r = f();
    let end = std::time::Instant::now();
    let duration = end - start;
    (r, duration)
}
