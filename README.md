# Shoup's Threshold Signatures

An implementation of threshold RSA signatures following Victor Shoup's
[*Practical Threshold Signatures*](https://www.shoup.net/papers/thsig.pdf)
with PSS support.
The implementation follows Protocol 1, with support for the more elegant Protocol 2 planned for later.

The tool exposes 4 utilities for key generation, signature share computation,
signature assembly from shares, and a one-shot signature computation from key shares.

## Key generation

```txt
Usage: shoup gen [OPTIONS] -t <THRESHOLD> -T <TOTAL> --pub <PUBKEY_OUT> <SHARES_DIR> <VK_DIR>

Arguments:
  <SHARES_DIR>  Directory to output the generated key shares to
  <VK_DIR>      Directory to output the generated verification shares to

Options:
  -b, --bits <BITS>            RSA key size in bits (2048, 3072, or 4096) [default: 3072]
  -t, --threshold <THRESHOLD>  Minimum number of shares required for signing
  -T, --total <TOTAL>          Number of total shareholders
  -p, --pub <PUBKEY_OUT>       Filename to output the public key to
  -h, --help                   Print help
```

## Individual share computation

```txt
Usage: shoup mint [OPTIONS] --in <INFILE> --key-share <KEY_SHARE> --out <OUTFILE>

Options:
  -i, --in <INFILE>            File to read the message from
  -k, --key-share <KEY_SHARE>  Key share file
  -o, --out <OUTFILE>          Output file for the signature share
      --rand <RAND>            File whose bytes are used as the PRNG seed (defaults to SHA-256 of the input file)
      --provable               Include a zero-knowledge proof of correct signing
  -h, --help                   Print help
```

## Signature assembly

```txt
Usage: shoup combine [OPTIONS] --in <INFILE> --pub <PUBKEY> --threshold <THRESHOLD> --total <TOTAL> --out <OUTFILE> <SIG_SHARES>

Arguments:
  <SIG_SHARES>  Directory containing the signature shares

Options:
  -i, --in <INFILE>            File to read the message from
  -p, --pub <PUBKEY>           Public key file
      --vk <VK>                Verification key file
      --vk-shares <VK_SHARES>  Directory containing the per-share verification keys
      --rand <RAND>            File whose bytes are used as the PRNG seed (defaults to SHA-256 of the input file)
  -t, --threshold <THRESHOLD>  Minimum number of shares required for signing
  -T, --total <TOTAL>          Total number of shareholders
  -o, --out <OUTFILE>          Output file for the combined signature
  -h, --help                   Print help
```
