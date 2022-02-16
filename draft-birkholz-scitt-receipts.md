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

Introduction

My cool solution [FIXME ref] is cool.

## Requirements Notation

{::boilerplate bcp14-tagged}

{: #mybody}
# Trust Assertions about Ledger Operations

;~~~~
;{::include simple-diagram.ascii}
;~~~~

# Trust Assertions using COSE Receipts

[TODO] Explain what the point is, why are we binding a cose_sign1 to a leaf that's part of a merkle tree?

In SCITT, the existence of a countersignature at a minimum means that:

- the COSE message signature has been validated by the countersigner according to a policy,
- the countersigner stored the COSE message and all validation evidence in an immutable ledger represented by a Merkle tree.

The trustworthiness of these properties relies on the trustwortiness of the countersigner, which in SCITT are the hardware and governance roots of trust.

# SCITT Receipt Structure

A SCITT Receipt is conceptually a variant of regular COSE countersigning {{-countersign}}. In COSE, a signature is generated over the payload and the protected header. In COSE Countersigning, the signature is generated over the payload and protected header of the COSE message to be countersigned and an optional protected header of the countersigner. In SCITT receipts, a signature is generated over a Merkle tree root. Together with a Merkle proof the signature confirms that a COSE message has been countersigned in a particular tree leaf. Typically, a single signature covers multiple countersigned COSE messages in the tree, but a given receipt always refers to a single COSE message.

In SCITT, the leaf of a Merkle tree is generated from a sequence of components, each with a specific purpose. This provides extensibility and flexibility for implementations. In this document, an initial set of standard components are defined.

Different to COSE (Counter)signatures, a SCITT Receipt is a tagged CBOR map. Map members with their integer labels and value types are described in the next section.

~~~
tagged_SCITT_receipt = #6.TBD(SCITT_receipt)

SCITT_Receipt = {
    int => any
}
~~~

## SCITT Receipt members

This section defines the SCITT Receipt members.

### The Service Key Member

[TODO] should this rather be a service id?

Label: 1
Value type: bstr


### Signing Algorithm member

The algorithm used for the signing operation.

Label: 2
Value type: int

The value is taken from the "COSE Algorithms" registry and must be one of the following:

- TBD does this list make sense?
- -7 (ES256)
- -35 (ES384)
- -8 (EdDSA)

### Merkle Tree Algorithm member

The algorithm used for the digest operation in the Merkle tree.

Label: 3
Value type: int

The value is taken from the "Named Information" registry and must be one of the following:

- 1 (sha-256)
- 7 (sha-384)
- TBD sha-512?
- TBD sha3?

### Merkle proof member

The Merkle proof. Used to compute the Merkle tree root starting from a leaf digest.

Label: 4
Value type: \[ + ProofElement \]

~~~
ProofElement = [
    left: bool
    digest: bstr
]
~~~


### Leaf components member

The components of the leaf. Used to compute the leaf digest. Each leaf component has a type where the type defines how to compute a digest of the component. This document defines a set of common types.

Label: 5
Value type: \[ + LeafComponent \]

~~~
LeafComponent = [
    type: int   ; type of leaf component
    * any       ; data specific to type
]
~~~

### Common leaf component types

#### COSE_Sign1 countersigning

Type value: 1

The COSE_Sign1 countersigning type defines how to bind to an existing COSE_Sign1 message.

~~~
COSESign1CounterSignLeafComponent = [
    type: 1
    sign_phdr: empty_or_serialized_map
]
; see RFC 8152 for empty_or_serialized_map
~~~

The component digest is computed as H(cbor(\[sign_phdr,phdr,payload,signature\])) where sign_phdr is included in the component itself, while phdr, payload, and signature are the fields from the COSE_Sign1 message to be countersigned.

#### CCF Ledger write-set digest

Type value: 2

~~~
CCFWritesetDigestLeafComponent = [
    type: 2     ; CCF writeset digest
    digest: bstr
]
~~~

The component digest is the digest field included in the component itself.

#### CCF Ledger commit evidence

Type value: 3

~~~
CCFCommitEvidenceLeafComponent = [
    type: 3      ; CCF commit evidence
    transaction_id: tstr
    hmac: bstr
]
~~~

The component digest is computed as H("ce:" + transaction_id + ":" + hex(hmac)).


## Signing and Verification Process

[TODO] is the ToBeSigned array a good idea?

In order to create a signature, a well-defined byte string ToBeSigned is needed. The following steps must be followed to generate ToBeSigned:

1. Compute leaf digest from leaf components:
~~~
LeafDigest := H(C_1 + C_2 + ... + C_n)
~~~

where C_i is the digest of the leaf component according to the type-specific algorithm.

2. Compute root digest from leaf digest and Merkle proof

~~~
h := LeafDigest
for [left, hash] in proof:
  h := H(hash + h) if left
       H(h + hash) else
root := h 
~~~

3. Compute final ToBeSigned: cbor(\[sig_alg, hash_alg, root\])

How to compute a countersignature:

1. Compute ToBeSigned using the steps described earlier.

2. Call the signature creation algorithm passing in K (the key to sign with), alg (the algorithm to sign with), and ToBeSigned (the value to sign).

3. Place the signature in the signature member of the SCITT receipt.

The steps for verifying a countersignature are:

1. Compute ToBeSigned using the steps described earlier.

2. Call the signature verification algorithm passing in K (the service key to verify with), sign_alg (the algorithm used sign with), ToBeSigned (the value to sign), and sign (the signature to be verified).


## COSE header parameter

This section defines a COSE header parameter for embedding one or more SCITT Receipts in the unprotected header of a COSE message:

Name: SCITT receipt
Label: TBD
Value Type: SCITT_Receipt / \[+ SCITT_Receipt\]
Value Registry: ?
Description: TBD

## The Full CDDL

TODO: CCF node vs service keys

~~~~ CDDL
tagged_SCITT_receipt = #6.TBD(SCITT_receipt)

SCITT_Receipt = {
    log_id: bstr // TODO what is this, UUID? advertise keys somewhere? DID? signed CTL?
    x5chain: bstr[] // node cert for CCF
    //service_key => bstr
    signature => bstr               ; Signature over root hash
    sign_alg => int
    merkle_alg => int
    proof => [ + ProofElement]      ; Merkle proof
    leaf_components => [ + LeafComponent]
}

ProofElement = [
    left: bool
    hash: Digest
]

Digest = bstr

; Each leaf component *type* defines how to derive
; a leaf component hash from the leaf component data.
LeafComponent = [
    type: int   ; type of leaf component
    * any       ; data specific to type
]

;; COSE-related leaf component types:

COSESign1CounterSignLeafComponent = [
    type: 1      ; COSE_Sign1 binding
    sign_phdr: empty_or_serialized_map
]
empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
; H(COSESign1CounterSignLeafComponent) = H(cbor([phdr,sign_phdr,payload,signature]))
; Note: phdr, payload, signature are all external

;; CCF leaf component types:

CCFWritesetDigestLeafComponent = [
    type: 2     ; CCF writeset digest
    digest: bstr
]
; H(CCFWritesetDigestLeafComponent) = digest

CCFCommitEvidenceLeafComponent = [
    type: 3      ; CCF commit evidence
    transaction_id: tstr
    hmac: bstr
]
; H(CCFCommitEvidenceLeafComponent) = H("ce:" + transaction_id + ":" + hex(hmac))
~~~~

# Privacy Considerations

Privacy Considerations

# Security Considerations

Security Considerations

# IANA Considerations

See Body {{mybody}}.

--- back
    
# Attic
    
~~~~ CDDL

tagged_SCITT_receipt = #6.TBD(SCITT_receipt)

SCITT_receipt = {
  ; FIXME how is alg authenticated?
  alg => int, ; hash alg applies to all digests
  service_key => bstr,
  signature => bstr,
  proof => bstr .cbor [ + ProofElement ],
  transaction_id => tstr,
  hmac => SHA_256, ; make this agile
  writeset-digest => SHA_256, ; make this agile
}

ProofElement = [
  left: bool,
  digest: SHA_256,
]

SHA_256 = bstr .size 32

~~~~
