
## Writeup

Refer to: https://blog.tanglee.top/2025/04/03/Revisiting-Garbled-Circuit.html

## Local Setup

First patch the source code fancy-garbling based on files in [patched-files](./patched_files/). Solve it locally with the following command:

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




