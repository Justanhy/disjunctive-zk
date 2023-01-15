# The Elliptic Curve Discrete Logarithm Problem
Suppose $E$ is an elliptic curve over $\Z/p\Z$ and $P \in E(\Z/p\Z)$. Given a multiple $Q$ of $P$, the *elliptic curve discrete log problem* is to find $n \in \Z$ such that $nP = Q$.

## Elliptic curve version of Schnorr's protocol
The Prover and Verifier agree on an elliptic curve $E$ over the field $F_n$, and a generator $G \in E / F_n$. 

- They both know $H \in E / F_n$
- Prover claims to know $x$ such that $H = x \cdot G$

**Protocol:**

Let $H = x \cdot G$ and let the witness that $P$ knows for the discrete log be $x_P$, we want to show that $x = x_P$

1. Prover generates random $r \in F_n$ and computes the point $U = r \cdot G$. The Prover sends the point $U$ to the Verifier
2. Verifier computes a random $c \in F_n$ and sends $c$ to the Prover.
3. Prover computes $z = r + c \cdot x_P \mod n$ and sends $z$ to the Verifier.
4. Verifier checks the following holds:
  $$
  \begin{align*}
  z \cdot G &= U + c \cdot H \\ 
  r \cdot G + c \cdot x_P \cdot G  &= r.G + c \cdot x \cdot G \\
  x  &=  x_P
  \end{align*}
  $$

  