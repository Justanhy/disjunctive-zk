# The Elliptic Curve Discrete Logarithm Problem
Suppose $E$ is an elliptic curve over $\Z/p\Z$ and $P \in E(\Z/p\Z)$. Given a multiple $Q$ of $P$, the *elliptic curve discrete log problem* is to find $n \in \Z$ such that $nP = Q$.

## Elliptic curve version of Schnorr's protocol
The Prover and Verifier agree on an elliptic curve $E$ over the field $F_n$, and a generator $G \in E / F_n$. 

- They both know $B \in E / F_n$
- Prover claims to know $x$ such that $B = x \cdot G$
- They want to prove this to the Verifier without revealing $x$

**Protocol:**

1. Prover generates random $r \in F_n$ and computes the point $A = r \cdot G$. The Prover sends the point $A$ to the Verifier
2. Verifier computes a random $c = HASH(G,B,A)$ and sends $c$ to the Prover.
3. Prover computes $m = r + c \cdot x \mod n$ and sends $m$ to the Verifier.
4. Verifier checks the following holds:
  $$
  \begin{align*}
  P &= m \cdot G -c \cdot B \\
    &= (r + c \cdot x) \cdot G - c \cdot B \\
    &= r \cdot G + c \cdot x \cdot G - c \cdot x \cdot G \\
    &= r \cdot G \\
    &= A
  \end{align*}
  $$

  