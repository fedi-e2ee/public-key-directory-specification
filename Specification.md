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
End-to-End Encryption.

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

## Concepts

### Identity Binding

This project will map ActivityPub Actor IDs to a set of one or more Public Keys. Optionally, some number of
Auxiliary Data records may also be supported, in order for other protocols to build atop the Public Key Directory.

The task of resolving aliases to Actor IDs is left to the client software.

### Public Key Encoding

Each public key will be encoded as an unpadded [base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5) string
prefixed by the cryptography protocol name followed by a colon.

For example: `ed25519:Tm2XBvb0mAb4ldVubCzvz0HMTczR8VGF44sv478VFLM`

### Protocol Signatures

Each digital signature will be calculated over the following information:

1. The value of the top-level `@context` attribute.
2. The value of the top-level `action` attribute.
3. The JSON serialization of the top-level `message` attribute.

To ensure domain separation, we will use [PASETO's PAE()](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition) function, with a tweak: We will insert the top-level
key (`@context`, `action`, `message`) before each piece.

For example:

```python
def signMessage(secret_key, message):
    messageToSign = preAuthEncode(
        b'@context',
        message.context,
        b'action',
        message.action,
        b'message',
        json_stringify(sort_by_key(message.message))
    )
    return crypto_sign(secret_key, messageToSign)
```

## Protocol Messages

This section outlines the different message types that will be passed from the Fediverse Server to the 
Public Key Directory Server.

Each protocol message will be a UTF-8 encoded JSON string. Dictionary keys **MUST** be unique within the same level.
Dictionary keys **SHOULD** be sorted. Participants **MAY** use whitespace, but it is not required.

Each protocol message will consist of the same structure:

```json5
{
  /* The version number used in @context may change in the future: */
  "@context": "https://github.com/fedi-e2ee/public-key-directory/v1",
  /* The action, such as AddKey or RevokeKey, goes here: */
  "action": "",
  "message": {
    /* 
    The actual message contents required for the specific action goes here.
    Its contents may vary from action to action.
    */
  },
  /* A signature calcualted over "@context", "action", and "message". */
  "signature": ""
}
```

### AddKey

An `AddKey` message associated with an Actor is intended to associate a new Public Key to this actor.

The first `AddKey` for any given Actor **MUST** be self-signed by the same public key being added.
Every subsequent `AddKey` must be signed by an existing, non-revoked public key. (Self-signing is
not permitted for any message after the first.)

#### AddKey Message Attributes

* `actor` -- **string (Actor ID)** (required): The canonical Actor ID for a given ActivityPub user.
* `time` -- **string (Timestamp)** (required): The current timestamp (ISO 8601-compatible).
* `public-key` -- **string (Public Key)** (required): The [encoded public key](#public-key-encoding).

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
