---
title: Countersigning Receipts in Support of Trustworthy Supply Chain Ledger Services
abbrev: SCITT Receipts
docname: draft-birkholz-scitt-receipts-latest
stand_alone: true
ipr: trust200902
area: Security
wg: TBD
kw: Internet-Draft
cat: std
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: M. Riechert
  name: Maik Riechert
  organization: Microsoft
  email: Maik.Riechert@microsoft.com
  country: UK
- ins: A. Delignat
  name: Antoine Delignat
  organization: Microsoft
  email: antdl@microsoft.com
  country: UK

normative:
  IANA.COSE-header-parameters:

informative:
  I-D.ietf-cose-countersign: countersign

--- abstract

A transparent and authentic ledger service in support of a supply chain's integrity, transparency, and trust requires all peers that contribute to the ledgers operations to be trustworthy and authentic. In this document, a countersigning variant is specified that enables trust assertions on merkle-tree based operations for global supply chain ledgers. A generic procedure how to produce payloads for signing and validation is defined and leverages solutions and principles from the Concise Signing and Encryption (COSE) space.

--- middle

# Introduction

This document defines a method for countersigning of COSE_Sign1 messages using CBOR Merkle Tree Signing.

## Requirements Notation

{::boilerplate bcp14-tagged}

{: #mybody}

## CBOR Merkle Tree Signing (CMTS)

When signing a Merkle tree, a list of leaves (payloads) are signed producing a single signature.
Each leaf together with the tree signature and a Merkle proof specific to the leaf are then packaged in a stand-alone structure for individual verification.
This document introduces this structure (CMTS_Sign1) for the case where there is a single signer.

### CMTS_Sign1 Structure

The CMTS_Sign1 structure is a CBOR array. The fields of the array in order are:

protected: The set of protected header parameters wrapped in a bstr.

unprotected: The set of unprotected header parameters as a map.

leaf: The Merkle Tree leaf content. The Leaf Algorithm header parameter determines how the content is preprocessed before passing it to the hash algorithm to produce the leaf digest.

proof: The Merkle proof as an array of [left, digest] pairs.

signature: The computed signature value as a bstr.

The CDDL fragment that represents the above text for CMTS_Sign1 follows.

~~~ cddl
CMTS_Sign1 = [
  protected: empty_or_serialized_map,
  unprotected: header_map,
  leaf: bstr,
  proof: [+ ProofElement],
  signature: bstr
]

header_map = {
  * int => any
}

empty_or_serialized_map = bstr .cbor header_map / bstr .size 0

ProofElement = [
    left: bool
    hash: bstr
]
~~~

### Common Header Parameters

#### Signing Algorithm member

The algorithm used for the signing operation.

Label: 1

Value type: int

The value is taken from the "COSE Algorithms" registry.

#### Hash Algorithm member

The algorithm used for the digest operation in the Merkle tree.

Label: 2

Value type: int

The value is taken from the "Named Information" registry.

#### Leaf Algorithm member

The algorithm used for preprocessing the leaf content to produce the input to the leaf digest operation.

Label: 3

Value type: int

Each algorithm must define a value for ToBeHashed which is the input to the leaf digest operation.

This document establishes a registry with initial members.

#### X.509 certificate chain

The X.509 certificate chain used for signing.

Label: 4

Value type: COSE_X509

#### Issuer

The issuer of the signed message. Syntax and semantics are application specific.

Label: 5

Value type: tstr

#### Key ID

The key identifier. Syntax and semantics are application specific.

Label: 6

Value type: bstr

### Leaf Algorithms

A new registry is established with the following initial leaf algorithms:

* 1: Identity leaf algorithm
* 2: Component leaf algorithm

#### Identity leaf algorithm

Value: 1

Leaf type: bstr

The leaf content is not processed further.

~~~
ToBeHashed = leaf
~~~

#### Component leaf algorithm

Value: 2

Leaf type: bstr .cbor \[ + LeafComponent \]

~~~ cddl
LeafComponent = bstr / [
    type: int   ; type of leaf component
    * any       ; data specific to type
]
~~~

Each leaf component is either an opaque digest or a structure with a type and optional data where the type defines how to compute a ComponentDigest.  The concatenation of all digests is the input to the leaf digest operation.

~~~
ToBeHashed := C_1 + C_2 + ... + C_n
~~~

This document establishes a registry with initial members.

### Verification Process

In order to verify a signature, a well-defined byte stream is needed. The Sig_structure is used to create the canonical form. The following steps must be followed to generate Sig_structure:

1. Compute leaf digest with input computed according to the Leaf Algorithm

~~~
LeafDigest := H(LeafAlgorithm(leaf))
~~~

2. Compute root digest from leaf digest and Merkle proof

~~~
h := LeafDigest
for [left, hash] in proof:
  h := H(hash + h) if left
       H(h + hash) else
root := h
~~~

3. Compute Sig_structure:

~~~ cddl
Sig_structure = [
  context: "Signature1",
  protected: empty_or_serialized_map,
  external_aad: bstr,
  root: bstr
]
~~~

The steps for verifying a signature are:

1. Generate a Sig_structure using the steps described earlier.

2. Create the value ToBeSigned by encoding the Sig_structure to a byte string, using the encoding described in Section X.

3. Call the signature verification algorithm passing in K (the key to verify with), alg (the algorithm used sign with), ToBeSigned (the value to sign), and sign (the signature to be verified).

## COSE_Sign1 countersigning leaf component

Type value: 1

The COSE_Sign1 countersigning leaf component type defines how to bind to an existing COSE_Sign1 message.

~~~
COSESign1CounterSignLeafComponent = [
    type: 1
    sign_phdr: empty_or_serialized_map
]
~~~

The digest of this leaf component is computed as:

~~~ cddl
Countersign_structure = [
  context: "CounterSignatureV2",
  body_protected: empty_or_serialized_map,
  sign_protected: empty_or_serialized_map,
  external_aad: bstr,
  payload: bstr,
  other_fields: [
    signature: bstr
  ]
]
ComponentDigest = H(cbor(Countersign_structure)
~~~

Note: This structure is identical to standard COSE V2 countersignatures.

body_protected, payload, and signature are of the target COSE_Sign1 message.  sign_protected is from the signer within the leaf component structure. external_aad is externally supplied data from the application encoded in a bstr. If this field is not supplied, it defaults to a zero-length byte string.

H is the Hash Algorithm used for the CMTS_Sign1 message.

## SCITT Receipt

A SCITT Receipt is defined as a CMTS_Sign1 message with the following characteristics:

1. One of the following Signing Algorithms is used:

  - -7 (ES256)
  - -35 (ES384)
  - -8 (EdDSA)

2. One of the following Hash Algorithms is used:

  - 1 (sha-256)
  - 7 (sha-384)

3. The Leaf Component algorithm is used.

4. The leaf components contain exactly one COSE_Sign1 countersigning leaf component. Additional leaf components may be included.

~~~ cddl
SCITT_Receipt = CMTS_Sign1
~~~

## COSE header parameter

This section defines a COSE header parameter for embedding one or more SCITT Receipts in the unprotected header of a COSE message:

Name: SCITT receipt
Label: TBD
Value Type: SCITT_Receipt / \[+ SCITT_Receipt\]
Value Registry: ?
Description: TBD

# Privacy Considerations

Privacy Considerations

# Security Considerations

Security Considerations

# IANA Considerations

See Body {{mybody}}.

--- back

