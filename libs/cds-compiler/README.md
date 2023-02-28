# [CDS94](https://link.springer.com/chapter/10.1007/3-540-48658-5_19) Compiler
In this implementation of the compiler, we will use 

- the elliptic curve version of Schnorr's discrete log protocol as our $\Sigma$-protocol, and 
- Shamir's secret sharing scheme (SSS)

to demonstrate the compilation of $\Sigma$-protocol into a disjunctive/threshold $\Sigma$-protocol for $n$ statements. 

> We will attempt to make the implementation as general as possible to open up for the future possibiity to take any $\Sigma$-protocol that suits our requirements and transform it into a $\Sigma$-protocol for $n$ statements.  

# The Witness Indistinguishable (WI) compilation 

In their paper, Cramer *et al* presents 2 primary ways to construct a WI protocol from a $\Sigma$-protocol $\mathcal P$ (Theorem 8 and 9). 

- Theorem 8 requires a smooth secret sharing scheme, and a HVZK $\Sigma$-protocol, while 
- Theorem 9 requires special honest verifier ZK (SHVZK) with at least a semi-smooth secret sharing scheme. 

Since, SSS is a smooth threshold secret sharing scheme (required for 8), and Schnorr's protocol is SHVZK (required for 9), we can choose either construction. 
*We will use **Theorem 8** in this project*.

**Theorem 8**. Given $\mathcal P$, $R_\Gamma$, $\Gamma$, and $\mathcal S(k)$ where

- $\mathcal P$ is a 3-round public coin ($\Sigma$-protocol) HVZK proof of knowledge for relation $R$, which satisfies the special soundness property.
- $\Gamma = \{ \Gamma(k) \}$ is a family of monotone access structures
- $\{\mathcal S(k)\}$ is a family of smooth secret sharing schemes such that the access structure of $\mathcal S(k)$ is $\Gamma(k)^*$
- $R_\Gamma$ is a relation where $((x_1,\ldots,x_m),(w_1,\ldots,w_m)) \in R_\Gamma$ if and only if ($\iff$) 

  - all $x_i$'s are of the same length $k$, and 
  - the set of indices $i$ for which $(x_i,w_i) \in R$ correspods to a qualified set in $\Gamma(k)$

**Then**, there exists a $\Sigma$-protocol that is witness indistinguishable for the relation $R_\Gamma$. **The proof of Theorem 8 and 9 is given in their paper.**

## Protocol Description
Let $A \in \Gamma$ denote the set of indices $i$ for which our prover $P$ knows a witness for $x_i$

1. For each $i \in \bar A$, $P$ runs a simulator on input $x_i$ to produce transcripts of conversations in the form $(m_1^i, c_i, m_2^i)$.
   - For each $i \in A$, $P$ inputs the witness $w_i$ for $x_i$ to $\mathcal P$ and takes what the prover $P^*$ in $\mathcal P$ sends as $m_1$ as $m_1^i$. Essentially we take the return value of the first round of $\mathcal P$ as our message $m_1^i$.
   - Finally, $P$ sends all $m_1^i$ to $V$, where $i = 1, \ldots, n$
   
2. $V$ chooses a $t$-bit string $s$ at random and sends it to $P$
3. $P$ forms challenges $c_i$ for $i \in A$, such that $share(c_i) \cup \{share(c_j)|j \in \bar A\}$ is a qualified set in $\Gamma$ consistent with $s$.  
   - For $i \in A$, $P$ uses it's knowledge of $w(x_i)$ to compute a valid $m_2^i$ for $(m_1^i, c_i)$ by running the prover's algorithm in $\mathcal P$.
   - $P$ then sends $c_i, m_2^i$ for $i = 1 ,\ldots, n$ to $V$. 
4. $V$ checks that all conversations $(m_1^i, c_i, m_2^i)$ would lead to acceptance by the verifier in $\mathcal P$
   - During this process, $V$ checks that $share(c_i)$ is consistent with secret $s$.
   - Accept if all true, otherwise reject. 

# Requirements
Schnorr
- Have a simulator we can call publically
- Compiler will interface through protocol (can't access prover directly(?))
- Function for each round of protocol

SSS
 - If we have $n$ statements, and we want $P$ to prove that they know $d$ out of $n$ we have to use SSS with threshold $n-d+1$.
 - API for qualified set completion.

