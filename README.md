```
go get github.com/MatthiasMi/go-crypto
```

This module is backwards compatible with x/crypto/openpgp,
so you can simply replace all imports of `golang.org/x/crypto/openpgp` with
`github.com/MatthiasMi/go-crypto/openpgp`.

A partial list of changes is here: https://github.com/ProtonMail/go-crypto/issues/21#issuecomment-492792917, and another feature to a privacy-preserving email provider's implementation is described below.

## Background
The [OpenPGP specification](https://tools.ietf.org/html/rfc4880) specifies formats for encrypted messages, signed messages, etc. and the [Go crypto library](https://github.com/ProtonMail/go-crypto) of my privacy-preserving email provider ProtonMail. This library is a fork of the [Go crypto library](https://github.com/golang/crypto) and a collection of cryptography-related functionality, including an OpenPGP implementation in the "openpgp" subdirectory.

One common criticism of OpenPGP is the lack of forward secrecy. The main goal of forward secrecy is to protect the security of past sessions against future compromises of secret keys and passwords by using a unique key for every session. There is an [old draft](https://tools.ietf.org/html/draft-brown-pgp-pfs-03) that proposed several methods for forward secrecy in OpenPGP.
While this draft was not accepted and is obsolete, it still provides a good opportunity:

1. Closely reading an RFC to pick up details of a concept
2. Making implementation decisions when details are omitted or open-ended
3. Integrating a feature into a large and complex codebase

This repo sets out to add an extension to go-crypto for demonstration purposes, implementing (part of) the aforementioned draft adding also some unit tests to test this new feature and to demonstrate to users how this feature should be used.
This draft leaves out many implementation details – which may be part of the reason it wasn’t adopted, but is not entirely uncommon either in cases where there’s no  well-defined RFC yet for a feature we want to implement. This means that it’s important to clearly keep track of and communicate implementation decisions.