## Async Rust implementation of [utls](https://github.com/refraction-networking/utls)
This library provides two functions:
```rust
async fn tls_handshake_as_client(
    stream: &mut TcpStream,
    sni_hostname: &[u8],
    tls_random_marker: u32,
    tls_server_data_marker: u32
) -> io::Result<()>
```

```rust
async fn tls_handshake_as_server<A>(
    mut stream: TcpStream,
    camouflage_server: A,
    tls_random_marker: u32,
    tls_server_data_marker: u32
) -> io::Result<TcpStream>
    where A: ToSocketAddrs +
             Send +
             'static
```