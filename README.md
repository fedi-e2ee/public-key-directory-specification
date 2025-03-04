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

It's worth keeping in mind that the Public Key Directory isn't *just* the Merkle Tree, it's an API built on top of a
Merkle Tree. To that end, you can query the API to retrieve every currently-trusted public key for a user, rather than
having to manually parse this information out of the data stored in the underling data structure.

### How Does This Help Non-Technical Users?

The Public Key Directory is a building block for developers. Our immediate audience for this specific component is 
necessarily somewhat technical.

However, the projects that build *atop* this building block should take pains to minimize the friction for non-technical
users. (That includes the other projects we will be opening in this GitHub organization!)

### Our Guiding Principals

All design decisions for this proposal have been influenced by the following guiding principals.

1. Build for people, and
2. Security over legacy

#### Build for People

The main goal of this project is to enable more people to securely communicate with each others.
From this it follows that we

* don't require any expert knowledge from the users of this system.
* minimize the number of steps a user has to take to use this system securely.
* value the privacy of the users, by only storing the minimal amount of information necessary and make it possible to delete data when the user demands it.
* clearly communicate errors and incidents to the users and by doing so give them a proper understanding of their security state.

As a side note, we don't consider companies as people.

#### Security Over Legacy

We want to build a system, which solves key management for people, nothing less and nothing more.
There are many ways to solves this problem and many existing solutions which could become part of our solution.
But we want to take the opportunity to focus on security and verifiability.
This means if we have the choice we will not take an existing solution, when this solution leads to an unwarranted increase in complexity or a security compromise. Even if this solution is an established standard and used by everyone else.


## Documents In Scope

* [Architecture](Architecture.md)
  \- This document succinctly describes how the Public Key Directory fits into the Fediverse.
* **[Specification](Specification.md)**
  \- This document contains the specification text in its entirety.
  1. [Introduction](Specification.md#introduction)
  2. [Concepts](Specification.md#concepts)
  3. [Threat Model](Specification.md#threat-model)
  4. [Protocol Messages](Specification.md#protocol-messages)
  5. [The Federated Public Key Directory](Specification.md#the-federated-public-key-directory)
  6. [Cryptography Protocols](Specification.md#cryptography-protocols)
  7. [Security Considerations](Specification.md#security-considerations)
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
