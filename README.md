# Rudraksh (KEM-poly64) Java Implementation

This repository contains a Java implementation of the Rudraksh lightweight MLWE-based KEM (KEM-poly64) described in the paper: https://tches.iacr.org/index.php/TCHES/article/view/12060

## Project Layout
- `src/main/java/org/security/rudraksh/RudrakshKEM.java` - PKE + KEM implementation
- `src/main/java/org/security/rudraksh/Ntt7681.java` - NTT/INTT for q=7681, n=64
- `src/test/java/org/security/rudraksh/AsconTest.java` - basic ASCON-XOF test

## Parameters (paper Table 1, KEM-poly64)
- n=64, l=9, q=7681
- p=2^10, t=2^3, B=2
- CBD parameters eta1=2, eta2=2

## Run
- Requires Java 11+ and Maven
- Build: `mvn -q -DskipTests package`
- Demo run: `mvn -q org.codehaus.mojo:exec-maven-plugin:3.1.0:java -Dexec.mainClass=org.security.rudraksh.RudrakshKEM`

## Use In Your Project
- Option A (local Maven install):
- Run: `mvn -q -DskipTests install`
- Add this dependency to your `pom.xml`:
```xml
<dependency>
  <groupId>org.security</groupId>
  <artifactId>security-protocole</artifactId>
  <version>1.0-SNAPSHOT</version>
</dependency>
```
- Option B (source include):
- Copy `src/main/java/org/security/rudraksh` into your project and build normally.

Example usage:
```java
import org.security.rudraksh.RudrakshKEM;

RudrakshKEM kem = new RudrakshKEM();
RudrakshKEM.KEMPk pk = new RudrakshKEM.KEMPk();
RudrakshKEM.KEMSk sk = new RudrakshKEM.KEMSk();

kem.kemKeyGen(pk, sk);
byte[][] ctAndK = kem.kemEncaps(pk);
byte[] ct = ctAndK[0];
byte[] kEnc = ctAndK[1];
byte[] kDec = kem.kemDecaps(pk, sk, ct);
```

## Test
- `mvn test`
- Note: this only runs JUnit tests (currently `AsconTest`) and does not execute `RudrakshKEM.main`.
- To exercise the KEM demo logic, run the main class using the `Run` section above.

## Community Review
I attempted to contact the core authors of the paper to clarify implementation details, but I was unable to receive a response. I am opening this repository to the community for review to identify any mismatches or issues in the implementation and to provide comments or improvements.

## Implementation Notes (Mismatch Fixes)
- v compression now uses `compress(cm, 32)` / `decompress(v, 32)` as specified for KEM-poly64 (Table 1 and Sec. 4.2). The modulus is `2^(t_bits + B) = 32` (t_bits=3, B=2).
- KEM key derivation follows Fig. 3: on success return `K'` directly from `G`, and on failure return `H(c, z)`. The extra `H(ct || K)` step was removed to match the paper.
- Ciphertext/public-key serialization is still 16-bit per coefficient (not bit-packed to 10-bit/5-bit). This keeps the implementation simple but does not match the paper’s bandwidth sizes; contributions to implement packing are welcome.
