To implement (the deprecated) [perfect forward secrecy draft for OpenPGP](https://tools.ietf.org/html/draft-brown-pgp-pfs-03)
in ProtonMail's [Go crypto library](https://github.com/ProtonMail/go-crypto)
the following methodology was chosen.

# Prerequisits
To get started fetching the sources with
`git clone https://github.com/ProtonMail/go-crypto.git && cd go-crypto/openpgp/`
the full tool chain is in place if all tests run successfully:
`go test`


# Methodology
+ Reading the [task](./Go-Task.pdf), RFC & linked resources attentively,
+ understanding the overall picture (+ identifying why this RFC was probably not adopted),
+ extracting sub-tasks characterized by keywords:
`"MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL"`,
+ understanding the overall code-base of Proton's go-crypto fork,
+ prioritizing work-load for given (time-)resources,
+ then, for each feature:
    + mentally/textually draft feature's architecture,
    + write unit test demonstrating the feature,
    + look-up feature details in RFC, and
    + iterate until the feature is implemented correctly.

## Summary
The following concepts are implied by the latter (assuming secure key deletion after use):
`short-lifetime key < "One-time key support" < Multiple one-time keys = "forward secrets"`.


Let `A` be Alice's public key, and `B` Bob's public key, then the following 3 steps describe Alice exchanging messages with Bob encrypted via appropriately keyed encryption function `E`, and receiving replies with perfect-forward secrecy (PFS) after step 2.


```text
1 | Alice  <------------------------- fetches Bob's keys ---------------------- Keyserver / Bob
2 | Alice  --------------- sends E_{k}(m), { E_k(k_i) | i = 1,2,...,n } -----------------> Bob
3 | Alice  <-- replies { E_{k_i}(m_i) | i = 1,2,...,n }, { E_{K}(K_j) | j = 1,2,...,m } -- Bob
...
```

In Step 2 of the sketched example protocol, Alice sends a message, and forward secrets  such that in the future Bob can reply with one-time messages.
In Step 3, `Bob` can reply up to `n`-times due to his stash of Alice's forward secrets `k_i`, and sends along `m` new forward secrets, i.e., encryption keys `K_j` for future use, providing multiple one-time keys for Alice, based on ephemeral 'symmetric' keys `k` respectively `K`.


# Implementation
While the following list of tasks could be identified and extracted from the RFC, only a certain subset can be mapped to a software solution, while some are to be considered infrastructure to-dos.

## Short-lifetime encryption keys

- [x] see [`write.go`](): Therefore when a public encryption key expires, an OpenPGP client MUST securely wipe the corresponding private key [4].

- [x] see [`AddForwardSecret`](): To simplify key management, short lifetime keys SHOULD be created as subkeys of their owner's long-term signature key.
- [ ] out of scope: As a user logs on, their mail client SHOULD retrieve and decrypt all messages from their mail server before deleting any newly-expired private keys. A "panic mode" MAY bypass this step.

- [ ] Clients receiving messages encrypted with an expired key MAY warn the sender that they should not use that public key again.

- [ ] Clients receiving messages encrypted with a revoked key MUST warn the sender that they should not use that public key again.
- [ ] Any relevant key revocation certificates MUST be included in the warning.

- [ ] Messages therefore MAY be stored temporarily encrypted with a short-lifetime key, but are unreadable once it has been deleted.
- [ ] Clients MUST allow messages to be stored encrypted under a long-term storage key.
- [ ] A mail client MAY implement its own secure storage facilities, or use those provided by other software.
- [ ] Messages SHOULD NOT be encrypted-to-self using a long-term public key.

### 2.1 Key generation and distribution

- [ ] batch key generation, out of scope: The client SHOULD minimise the time required by the user to complete this operation.

- [ ] Multiple forward secret Elgamal keys MAY therefore use the same prime modulus with minimal security reduction.

- [ ] architecture, out of scope: Submission and retrieval of generally-available public keys SHOULD be performed automatically by software.

- [ ] If an OpenPGP client has more than one valid encryption key available for a given message recipient, the key nearest its expiration date MUST be used.

- [ ] Encryption keys SHOULD be certified by a user's long-term signature key to allow their verification by other users.

### 2.2 Key surrender

- [ ] Before an OpenPGP client exports a private key as plaintext, the associated public key MUST be revoked and redistributed.
- [ ] A "reason for revocation" signature subpacket MUST be included in the key revocation specifying "Key material has been compromised" (value 0x02).
- [ ] The least compromising key required MUST be the one surrendered.

## 3. One-time keys

- [x] Every time a user sends a message encrypted with a public key whose signature includes a one-time key support subpacket, they SHOULD include a new one-time public subkey for the recipient to encrypt any reply with.

- [ ] If PGP/MIME [7] support is available, new key(s) MUST be sent in a separate application/pgp-keys MIME bodypart.
- [ ] One-time subkeys MUST NOT be exported by their recipient to a third party, particularly a key server.
- [x] Users still MUST possess a relatively long-lived encryption key.

- [x] "One-time key support" subpackets MUST be included in the hashed area of a signature.
- [x] One-time key flag subpackets MUST be included in the hashed area of a signature.

- [x] When encrypting messages to a key with a signature containing a one-time feature subpacket, at least one new public encryption subkey MUST be included in the message.
- [x] This key MUST be signed by the sender's long-term signature key and include a one-time key flag subpacket.
- [x] The lifetime of a one-time subkey SHOULD be set to as short a period as possible given the expected response time of the recipient.

- [x] A client MUST include further new public encryption subkeys if it believes a message will receive multiple replies.
Each reply SHOULD be encrypted with a different subkey if available.
- [x] Clients MUST delete a one-time subkey after successfully encrypting data using it.
- [x] They SHOULD use a one-time subkey, if available, in preference to a short-lifetime key.

## 4. Secure and decentralised e-mail transport

- [ ] OpenPGP mail clients therefore SHOULD deliver messages directly to the recipient's mail server, and SHOULD use any available lower layer security services to protect the links used to deliver messages.

- [ ] Where OpenPGP keys are used in such services, they SHOULD NOT be used to encrypt keying material that can later be decrypted if they are compromised.
- [ ] Ideally, they SHOULD be used only to authenticate a forward-secret key negotiation protocol such as Diffie-Hellman [3].
- [ ] At the least, new short-lifetime key pairs SHOULD be generated for key encryption use.

- [ ] Direct delivery of mail can reveal the sender and recipient of messages to traffic analysts.
- [ ] Clients MAY use anonymous remailers [11] or IP services [12] to mask this information.



# Implementation details
Making OpenPGP (optionally) forward secure using one-time keys to encrypt symmetric session keys can be achieved following these general steps:

1. Introduce a new subpacket enabling the one-time keys.
2. If sender and receiver enable the forward secrecy feature, a newly generated one-time public key and its signature by the entity's primary key are used for their next message.
3. Forward secrets are marked with a flag.
4. Short lifetime is enforced making keys for one-time use only and deleting them upon successful decryption.
5. The number of keys, assuming the number of expected replies, is variable just as their lifetime, before new keys are required.

## Tests

1. `TestForwardSecrecy` checks that the ForwardSecrecy feature is enabled correctly.

2. `TestEncryptionWithForwardSecrecy` is an example protocol run with ForwardSecrecy enabled, where Alice sends several encrypted messages to Bob, until his forward secrets are exhausted at which point their communication falls back as if ForwardSecrecy is not enabled.


# Further Suggestions / Remarks about the code
Generally, `validateElGamalParameters` could implement (partial) factorization (up to some threshold) of `p-1`, ensuring large enough
order of `g`.