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

We propose a specification for a Public Key Directory server, which acts as both a storage layer and shim for a Merkle
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
Auxiliary Data records may also be supported, in order for other protocols to build atop the Public Key Directory(PKD).

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
    messageToSign = preAuthEncode([
        b'@context',
        message.context,
        b'action',
        message.action,
        b'message',
        json_stringify(sort_by_key(message.message))
    ])
    return crypto_sign(secret_key, messageToSign)
```

### Key Identifiers

Every time an `AddKey` message is accepted by the Public Key Directory, it will generate a 256-bit random
unique `key-id` for that public key. This value is not secret or sensitive in any way, and is only used to
point to an existing public key to reduce the amount of rejected signatures software must publish.

Every message except revocations and the first `AddKey` for an Actor **SHOULD** include a `key-id` value.

The `key-id` attribute **MUST NOT** be an encoded representation of the public key.

The `key-id` is not covered in the protocol messages being signed. Instead, it is a hint to the signature 
validation software which public key to select when there is more than one option. Their values are totally
arbitrary and, aside from uniqueness, serve no other purpose.

### Revocation Tokens

A revocation token is a compact token that a user can issue at any time to revoke an existing public key.
If they issue a revocation against their only public key, the Public Key Directory will treat it as a
BurnDown.

Revocation tokens are base64url-encoded strings in the following format:

```
tmp := version || REVOCATION_CONSTANT || public_key 
revocation_token := base64url_encode(tmp || Sign(secret_key, tmp))
```

Where:
 * `version` is the version of the protocol being used (currently, `FediPKD1`).
 * `REVOCATION_CONSTANT` is a domain-separated constant for revoking an existing key. Its current value is
   the `0xFE` byte repeated 32 times followed by `revoke-public-key`.
 * `Sign(sk, m)` performs the digital signature algorithm corresponding to the current protocol version.
   (Currently, Ed25519.)

These values **MAY** be encrypted and stored in case of emergency. There is no temporal or random component
to the message format, so they can be issued at any time.

If you stumble upon another user's secret key, generating a revocation token should be straightforward.

### Auxiliary Data

The Public Key Directory will advertise a list of Auxiliary Extensions, which can be developed at a later
time, that define the types and formats of Auxiliary Data that will be accepted by a particular PKD server.

For example, a PKD Server may include `age-v1` in its list of Auxiliary Extensions, which in turn allows
users to submit `AddAuxData` and `RevokeAuxData` messages that include an [age v1](https://github.com/FiloSottile/age)
public key.

The intent of Auxiliary Data is to allow developers to build their PKD extensions in order to integrate  with their own
systems without interfering with the normal operation of the PKD server. This also allows us to be stricter about our
cryptography primitive choices.

For example, if someone wanted to build a protocol that used `ssh-rsa` public keys, they can without us needing to
natively support RSA at all. They'll just need to shove them into Auxiliary Data.

#### Auxiliary Data Identifiers

Every Auxiliary Data will have a deterministic unique identifier based on the extension and the contents of the data.

It can be calculated as follows, using the `preAuthEncode` function from PASETO (PAE):

```python
def getAuxDataId(aux_type, data):
    return hmac_sha256(
        b'FediPKD1-Auxiliary-Data-IDKeyGen' # this key is a constant for v1 of this protocol specification
        PAE([
            b'aux_type',
            aux_type,
            b'data',
            data
        ])
    )
```

## Protocol Messages

This section outlines the different message types that will be passed from the Fediverse Server to the 
Public Key Directory server.

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

Some protocol messages **SHOULD** also include a top level `"key-id"` attribute, which will help
implementations select one of many public keys to validate the signature. If no `key-id` is provided,
each valid public key **MAY** be tried.

### AddKey

An `AddKey` message associated with an Actor is intended to associate a new Public Key to this actor.

The first `AddKey` for any given Actor **MUST** be self-signed by the same public key being added.
Every subsequent `AddKey` must be signed by an existing, non-revoked public key. (Self-signing is
not permitted for any message after the first.)

The first `AddKey` will not have a `key-id` outside of the message.  Every subsequent `AddKey` for
a given Actor **SHOULD** have a `key-id`.

Like most messages, `AddKey` must be sent from an Fediverse Server that supports HTTP Signatures.

#### AddKey Attributes

* `message` -- **map**
  * `actor` -- **string (Actor ID)** (required): The canonical Actor ID for a given ActivityPub user.
  * `time` -- **string (Timestamp)** (required): The current timestamp (ISO 8601-compatible).
  * `public-key` -- **string (Public Key)** (required): The [encoded public key](#public-key-encoding).
* `key-id` -- **string(Key Identifier)** (optional): See [Key Identifiers](#key-identifiers)

### RevokeKey

A `RevokeKey` message marks an existing public key as untrusted. There is no undo operation for public
key revocation. `RevokeKey` is but one mechanism for public key revocation, intended to be used by
the Actor that normally possesses the key.

Attempting to issue a `RevokeKey` **MUST** fail unless there is another public key associated with this
Actor. The key used to sign the `RevokeKey` cannot be the same as the key being revoked.

See [BurnDown](#burndown) for clearing all keys and starting over (unless [Fireproof](#fireproof) was
ever issued).

#### RevokeKey Attributes

* `message` -- **map**
  * `actor` -- **string (Actor ID)** (required): The canonical Actor ID for a given ActivityPub user.
  * `time` -- **string (Timestamp)** (required): The current timestamp (ISO 8601-compatible).
  * `public-key` -- **string (Public Key)** (required): The [encoded public key](#public-key-encoding).
* `key-id` -- **string(Key Identifier)** (optional): The key that is signing the revocation.

### RevokeKeyThirdParty

This is a special message type in two ways:

1. It can bypass the Fediverse server entirely, and be submitted directly to the Public Key Directory.
2. It can be issued by an unrelated third party.

If the user doesn't possess any other public keys, this message bypasses the usual `RevokeKey` 
restriction where the user continue to must have a valid public key. Instead, the Actor will be
treated as if they ran a successful `BurnDown`, and allows them to start over.

Because the contents of this revocation token are signed, no `signature` is needed outside of the
`message` map. Nor is any `key-id`.

#### RevokeKeyThirdParty Attributes

* `revocation-token` --**string (Signature)** (required): See [Revocation Tokens](#revocation-tokens).

### MoveIdentity

This moves all the mappings from the old Actor ID to the new Actor ID.

The message **MUST** be signed by a valid secret key for the `old-actor`, but the HTTP Signature **MAY** 
come from either Fediverse Server instance.

This message **MUST** be rejected if there are existing public keys for the target `new-actor`.

#### MoveIdentity

* `message` -- **map**
    * `old-actor` -- **string (Actor ID)** (required): Who is being moved.
    * `new-actor` -- **string (Actor ID)** (required): Their new Actor ID.
    * `time` -- **string (Timestamp)** (required): The current timestamp (ISO 8601-compatible).
* `key-id` -- **string(Key Identifier)** (optional): The key that is signing the revocation.

### BurnDown

A `BurnDown` message acts as a soft delete for all public keys and auxiliary data for a given
Actor, unless they have previously issued a `Fireproof` message to disable this account recovery
mechanism.

This allows a user to issue a self-signed `AddKey` and start over.

#### BurnDown Attributes

* `message` -- **map**
    * `actor` -- **string (Actor ID)** (required): The canonical Actor ID for a given ActivityPub user.
    * `time` -- **string (Timestamp)** (required): The current timestamp (ISO 8601-compatible).
* `key-id` -- **string(Key Identifier)** (optional): The key that is signing the revocation.

### Fireproof

Where `BurnDown` resets the state for a given Actor to allow account recovery, `Fireproof` opts out of
this recovery mechanism entirely.

The only way to un-fireproof an Actor is to use a Revocation token on their only Public Key. See
[the relevant Security Considerations section](#revocation-and-account-recovery).

#### BurnDown Attributes

* `message` -- **map**
    * `actor` -- **string (Actor ID)** (required): The canonical Actor ID for a given ActivityPub user.
    * `time` -- **string (Timestamp)** (required): The current timestamp (ISO 8601-compatible).
* `key-id` -- **string(Key Identifier)** (optional): The key that is signing the revocation.

### AddAuxData

See [Auxiliary Data](#auxiliary-data) above for an explanation.

These messages will append some Auxiliary Data to an Actor, provided that the Public Key Directory server supports the
relevant extension, and the data provided conforms to whatever validation criteria the extension defines.

#### AddAuxData Attributes

* `message` -- **map**
  * `aux-type` -- **string (Auxiliary Data Type)** (required): The identifier used by the Auxiliary Data extension.
  * `aux-data` -- **string** (required): The auxiliary data.
  * `aux-id` -- **string** (optional): See [Auxiliary Data Identifiers](#auxiliary-data-identifiers). If provided, the server
    will validate that the aux-id is valid for the given type and data. 
  * `time` -- **string (Timestamp)** (required): The current timestamp (ISO 8601-compatible).
* `key-id` -- **string(Key Identifier)** (optional): The key that is signing the revocation.

### RevokeAuxData

This revokes one [Auxiliary Data](#auxiliary-data) record for a given Actor.

#### RevokeAuxData Attributes

* `message` -- **map**
  * `aux-type` -- **string (Auxiliary Data Type)** (required): The identifier used by the Auxiliary Data extension.
  * `aux-data` -- **string** (optional): The auxiliary data.
  * `aux-id` -- **string** (optional): See [Auxiliary Data Identifiers](#auxiliary-data-identifiers). If provided, the server
    will validate that the aux-id is valid for the given type and data.
  * `time` -- **string (Timestamp)** (required): The current timestamp (ISO 8601-compatible).
* `key-id` -- **string(Key Identifier)** (optional): The key that is signing the revocation.

Note that either `message.auth-data` **OR** `message.aux-id` is required in order for revocation to succeed.

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

### Revocation and Account Recovery

Public key revocation is a thorny topic, and is difficult to balance for all threat models.

Some users may want the ability to re-establish themselves in the protocol, no matter how badly
they mismanage their keys. Thus, their instance being able to issue a [`BurnDown`](#burndown) is
essential as a break-glass fature for account recovery.

Other users may expect a higher degree of security, and may wish to opt out of this `BurnDown`
capability from their Fediverse instance. Once they have opted out, there is no way to undo
opting out. It's a one-way door to prevent misuse.

[`RevokeKeyThirdParty`](#revokekeythirdparty) is an emergency feature that allows anyone to
pull the plug on a compromised identity key. Every time one is issued, the community should
pay close attention to the Actor affected by it.

If a third party issues a `RevokeKeyThirdParty` with a valid revocation token for a fireproof
user's only valid public key, the system **MUST** prioritize handling the key compromise as a
higher priority. This means that `Fireproof` is ignored in this edge case.
