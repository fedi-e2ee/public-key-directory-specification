# Public Key Directory Specification

This document defines the FediE2EE-PKD (Fediverse End-to-End Encryption Public Key Directory), which consists of 
ActivityPub-enabled directory server software, a protocol for communicating with the directory server, and integration
with a transparent, append-only data structure (e.g., based on Merkle trees).

* Current version: v0.0.1
* Authors: [Soatok Dreamseeker](https://github.com/soatok)

## Introduction

### Motivation

One of the challenges for building any cryptographic protocol in federated or peer-to-peer protocols is establishing
some sort of identity for the other parties. This is as true of systems for signing Git commits as it is for 
end-to-end encryption. 

This challenge is not unique to federated systems and is usually solved by some sort of Public Key Infrastructure (PKI).

The classic SSH approach to addressing this problem is "Trust On First Use". Simple yet effective in many threat models.

The earliest designs for SSL/TLS required the use of Certificate Authorities, whose public keys would be provided by
the Operating System as a root of trust. Each CA's public key would then be used to sign a cadre of intermediate
certificates, which could in turn be used to sign individual servers' public keys (in the form of Certificates).

The OpenPGP solution to this problem is called Web of Trust, which involves a long chain of folks signing each other's
public keys. The reasoning goes, if your friend's public key was signed by Linus Torvalds, they're probably a legitimate
Linux kernel contributor. However, if you're trying to establish the identity of someone without strong pre-existing
social ties, this is not a very helpful system.

This historical context is an oversimplification, of course. It's possible to use SSH with certificate authorities, for
example.

In recent years, the cryptography community has moved towards transparency ledgers for important cryptographic designs.
TLS certificates are now required to be published in a Certificate Transparency ledger. WhatsApp now uses a mechanism
called [Key Transparency](https://engineering.fb.com/2023/04/13/security/whatsapp-key-transparency/) to secure their
End-to-Eend Encryption.

To that end, we hope to build a PKI for the Fediverse primarily focused on transparency logs. 

The primary use case is to support End-to-End Encryption for ActivityPub messages between users. However, we also want
to support developers seeking supplemental use cases (e.g., exchanging [age](https://github.com/FiloSottile/age) public
keys for encrypted file sharing).

### This Document

We propose a specification for a Public Key Directory server, which acts a both a storage layer and shim for a Merkle
Tree-based append-only data ledger.

We specify a protocol for communicating with the Public Key Directory server, which will mostly be performed in the
context of a Fediverse server.

We further specify a public JSON REST API for reading public keys for specific Fediverse users, that the Public Key
Directory software will implement. 

Finally, we discuss some security considerations for building atop our Public Key Directory server.

### Out Of Scope

Client software behavior is not in scope for this document.

Fediverse server behavior is largely out of scope for this document, provided it correctly implements the protocol to
communicate with the Public Key Directory.

Backwards compatibility with existing systems (i.e., the PGP ecosystem) is a non-goal.

### Notation and Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in 
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## Protocol Messages

### AddKey

### RevokeKey

### MoveIdentity

### BurnDown

### Fireproof

### AddAuxData

### RevokeAuxData

## The Federated Public Key Directory

### JSON REST API

### Gossip Protocol

### SigSum Integration

## Security Considerations

### Cryptographic Agility

The cryptographic components specified by the initial version of this specification are
[Ed25519](https://datatracker.ietf.org/doc/html/rfc8032) (which includes SHA-512 internally) and SHA-256 (for SigSum).

Future versions of this specification should make an effort to minimize the amount of complexity for implementors.
To that end, cryptographic agility will only be satisfied by the introduction of new protocol versions, rather than
enabling the hot-swapping of cryptographic primitives by configuration.

### Interoperability As A Non-Goal

Other software and protocols are welcome to be compatible with our designs, but we will make no effort to support
incumbent designs or protocols (i.e., the PGP ecosystem and its Web Of Trust model).
