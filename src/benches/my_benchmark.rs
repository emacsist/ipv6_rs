use criterion::{criterion_group, criterion_main, Criterion};

use ipv6_rs::find_addr_vec;

fn criterion_benchmark(c: &mut Criterion) {
    let v = find_addr_vec("2409:8945:3ef:8863:68ae:9a0d:c00a:2297");
    println!("{:?}", v);
    //中国|河南
    c.bench_function("ipv6_rs", |b| b.iter(|| find_addr_vec("2409:8945:3ef:8863:68ae:9a0d:c00a:2297")));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
