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

## Test
- `mvn test`

## Community Review
I attempted to contact the core authors of the paper to clarify implementation details, but I was unable to receive a response. I am opening this repository to the community for review to identify any mismatches or issues in the implementation and to provide comments or improvements.
