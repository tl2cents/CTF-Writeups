
## Writeup

Solve it locally with the following command:

```bash
cargo build --release
```

Run server:

```bash
./target/release/server 127.0.0.1:31004 --circuit aes.txt --key fabda3d3c69ccaec4ad19dc15ab8dff5
```

Run malicious client:

```bash
 ./target/release/malicious_client --circuit aes.txt --input 00000000000000000000000000000000 127.0.0.1:31004
```




