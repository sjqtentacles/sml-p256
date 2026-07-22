# sml-p256

[![CI](https://github.com/sjqtentacles/sml-p256/actions/workflows/ci.yml/badge.svg)](https://github.com/sjqtentacles/sml-p256/actions/workflows/ci.yml)

NIST P-256 (secp256r1) ECDH and ECDSA signature verification in pure
Standard ML. Dual-compiler (MLton + Poly/ML) with byte-identical test
output; zero runtime dependencies.

> **Security note**: pure SML cannot provide constant-time guarantees, so
> this library is suitable for verification, interoperability testing, and
> experimentation — not for handling high-value private keys in adversarial
> settings.

## Installation

```
smlpkg add github.com/sjqtentacles/sml-p256
smlpkg sync
```

## Usage

```sml
(* Public key derivation: 32-byte scalar -> uncompressed SEC1 point
   (0x04 || X || Y, 65 bytes). All payloads are raw byte strings, never hex. *)
val pub = P256.generatePublic priv

(* ECDH: returns the shared point's X coordinate (32 bytes), or NONE on a
   bad peer key (off-curve / identity / malformed). *)
val secret = P256.ecdh {privateKey = priv, peerPublic = theirPub}

(* ECDSA verify over SHA-256(message); the signature is DER
   SEQUENCE { INTEGER r, INTEGER s }. Total: malformed input => false. *)
val ok = P256.ecdsaVerify {publicKey = pub, message = msg, signatureDer = der}

(* Curve-membership check on an uncompressed public key. *)
val onCurve = P256.isOnCurve pub
```

## Example

`make example` builds and runs [`examples/demo.sml`](examples/demo.sml), which
exercises `generatePublic`, `ecdh`, `ecdsaVerify`, and `isOnCurve` against the
published RFC 6979 Appendix A.2.5 test vectors (literal fixed scalars/keys,
never a fabricated private key; output is byte-identical under MLton and
Poly/ML):

```
=== sml-p256 demo (RFC 6979 Appendix A.2.5 vectors) ===

generatePublic(priv) matches published pub = true
public key (hex)      = 0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299

isOnCurve(G)           = true
isOnCurve(pub)         = true
isOnCurve(identity)    = false

ecdh(1, pub).x  = Ux    = true
ecdh(priv, G).x = Ux    = true

ecdsaVerify(pub, "sample", sig)  = true
ecdsaVerify(pub, "tample", sig)  = false
```

## API

See [`p256.sig`](lib/github.com/sjqtentacles/sml-p256/p256.sig). Conventions
shared with the sjqtentacles crypto family:

- byte payloads are raw byte strings (one char per byte), never hex;
- decoders are total — malformed input returns `NONE`/`false`, never a
  partial value or an uncaught exception.

## Build & test

```
make test        # build + run tests under MLton
make test-poly   # build + run tests under Poly/ML
make all-tests   # both compilers + byte-identical output gate
```

The suite (22 assertions) verifies against published vectors, including
RFC 6979 Appendix A.2.5 (P-256/SHA-256 deterministic ECDSA) — expected
values come from the RFC, not from this implementation.

## License

MIT — see [LICENSE](LICENSE).
