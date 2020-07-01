# usage

```rust
use ipv6_rs::find_addr_vec;

let v = find_addr_vec("2409:8945:3ef:8863:68ae:9a0d:c00a:2297");

println!("{:?}", v);
```

# bench

```bash
ipv6_rs                 time:   [3.7359 us 3.7383 us 3.7406 us]
                        change: [+0.7070% +0.9462% +1.1268%] (p = 0.00 < 0.05)
                        Change within noise threshold
```