//! Criterion benchmarks: key generation, signing (with and without the fault check) and
//! verification for every parameter set. Run with
//! `cargo bench --features all-parameter-sets -- <filter>`.

use criterion::{Criterion, criterion_group, criterion_main};
use slhsig::*;
use std::hint::black_box;

fn bench_set<P: ParameterSet>(c: &mut Criterion) {
    let mut group = c.benchmark_group(P::NAME);
    if P::NAME.ends_with('s') {
        group.sample_size(10); // "s" sets sign slowly by design
    }
    let ctx = Context::new(b"bench").unwrap();
    let msg = [0x5au8; 1024];

    group.bench_function("keygen", |b| b.iter(|| SigningKey::<P>::generate().unwrap()));

    let sk = SigningKey::<P>::generate().unwrap();
    let vk = sk.verifying_key();
    group.bench_function("sign (default: redundant)", |b| {
        b.iter(|| sk.sign(black_box(&msg), ctx).unwrap())
    });
    for (label, mode) in
        [("sign (verify)", FaultCheck::Verify), ("sign (no fault check)", FaultCheck::None)]
    {
        let key = SigningKey::<P>::from_bytes(&sk.to_bytes()).unwrap().with_fault_check(mode);
        group.bench_function(label, |b| b.iter(|| key.sign(black_box(&msg), ctx).unwrap()));
    }
    let sig = sk.sign(&msg, ctx).unwrap();
    group.bench_function("verify", |b| b.iter(|| vk.verify(black_box(&msg), ctx, &sig).unwrap()));
    group.finish();
}

fn benches(c: &mut Criterion) {
    bench_set::<Sha2_128s>(c);
    bench_set::<Sha2_128f>(c);
    bench_set::<Sha2_192s>(c);
    bench_set::<Sha2_192f>(c);
    bench_set::<Sha2_256s>(c);
    bench_set::<Sha2_256f>(c);
    bench_set::<Shake128s>(c);
    bench_set::<Shake128f>(c);
    bench_set::<Shake192s>(c);
    bench_set::<Shake192f>(c);
    bench_set::<Shake256s>(c);
    bench_set::<Shake256f>(c);
}

criterion_group!(group, benches);
criterion_main!(group);
