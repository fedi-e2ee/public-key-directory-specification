# Public Key Directory Server Specification

This repository contains the specification for a **Public Key Directory** for the Fediverse.

> This is still a work in progress.

## What Is This All About?

The hardest part of designing end-to-end encryption for the Fediverse is actually a **Key management** problem, which
can be summed up as one question:

> How do you know which public key belongs to a stranger you want to chat privately with?

How ever you decide to initially answer that question, the obvious follow-up question is:

> How do you know that you weren't deceived?

And if you repeat this exercise, you will eventually reinvent a trust model for a public key infrastructure.

### Our Proposal

Our solution is to require all relevant actions (public key enrollment and revocation) be published immediately onto an 
append-only data structure (i.e., a Merkle tree). In the cryptographic literature, this is called "Key Transparency".

The Public Key Directory vends a user's public keys that can be used with digital signature algorithms, and includes a
machine-verifiable proof of when each public key was enrolled. This is useful for establishing a baseline, minimal level
of trust that a given public key is correct for the party you wish to talk to.

Additional manual key verification mechanisms (key fingerprints, safety numbers, etc.) are out-of-scope but totally 
permitted for technical users in higher-level protocols. Really, we're trying to do better than Trust on First Use 
(TOFU), so [Johnny can finally encrypt](https://people.eecs.berkeley.edu/~tygar/papers/Why_Johnny_Cant_Encrypt/OReilly.pdf). 

Other applications can build atop our Public Key Directory design to build advanced use cases (i.e., authenticated key 
exchanges for end-to-end encryption).

### How Does This Help Non-Technical Users?

The Public Key Directory is a building block for developers. Our immediate audience for this specific component is 
necessarily somewhat technical.

However, the projects that build *atop* this building block should take pains to minimize the friction for non-technical
users. (That includes the other projects we will be opening in this GitHub organization!)

## Documents In Scope

* [Architecture](Architecture.md)
  \- This document succinctly describes how the Public Key Directory fits into the Fediverse.
* **[Specification](Specification.md)**
  \- This document contains the specification text in its entirety.
* [Test Vectors](Test-Vectors.md)
  \- This document will contain test vectors for the protocols used in the Public Key Directory.

## Reference Implementation

(Coming soon!)

## Historical Development Blogs

This section includes some highlights that may be worth considering to understand the technical underpinnings of our
design. Reading them is not mandatory, but should provide insight into how we approached these problems.

1. [Towards Federated Key Transparency](https://soatok.blog/2024/06/06/towards-federated-key-transparency) (June 2024)
    * This blog post kicked this project off. It explains the motivation and how it fits into the goal of delivering
      "end-to-end encryption for the Fediverse".
2. [Key Transparency and the Right to be Forgotten](https://soatok.blog/2024/11/21/key-transparency-and-the-right-to-be-forgotten/)
   (November 2024)
    * This blog post describes how we square the auditable, append-only nature of Merkle Trees with a desire to not make
      complying with a nation's *Right To Be Forgotten* technically impossible.

## Extensions for Auxiliary Data

See the [Extensions](https://github.com/fedi-e2ee/fedi-pkd-extensions) repository.
