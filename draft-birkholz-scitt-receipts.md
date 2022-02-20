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
  IANA.named-information:
  RFC8949:
  RFC9162:

informative:
  I-D.ietf-cose-countersign: countersign

--- abstract

A transparent and authentic ledger service in support of a supply chain's integrity, transparency, and trust requires all peers that contribute to the ledgers operations to be trustworthy and authentic. In this document, a countersigning variant is specified that enables trust assertions on merkle-tree based operations for global supply chain ledgers. A generic procedure how to produce payloads for signing and validation is defined and leverages solutions and principles from the Concise Signing and Encryption (COSE) space.

--- middle

# Introduction

This document defines a method for countersigning of COSE_Sign1 messages when using Merkle Trees.

## Requirements Notation

{::boilerplate bcp14-tagged}

{: #mybody}

# Cryptographic Components

## Definition of the Merkle Tree

NOTE: This section is purely mathematical, no CBOR here!

leaves (opaque content)

computation of root (Merkle tree hash)

inclusion proofs:

- generation
- verification

Note: This is mostly {{RFC9162}} except that the Merkle Tree Hash algorithm currently treats leaves and intermediate nodes the same during hashing.

## Signing of the tree root

COSE_Sign1 is used for signing the tree root. The unprotected header must be empty. The payload is the binary root digest, for example 32 bytes for SHA-256. A new COSE header parameter to identify the Merkle tree hash algorithm is registered, see next section.

~~~ cddl
SignedRoot = COSE_Sign1
~~~

Comparison: {{Section 4.10 of RFC9162}}, which signs over the timestamp, tree size, root, and optional extensions using a DER-encoded structure.

### Hash Algorithm parameter

The algorithm used for the digest operation in the Merkle tree. When present, this parameter MUST be placed in the protected header bucket.

This parameter is used for verifying inclusion proofs, see Receipts in {{receipts}}.

Label: TBD

Value type: int

The value is taken from the {{IANA.named-information}} registry.

[TODO] Alternatively, this could be moved into the payload which could be made into a structure rather than the raw root hash. This would reduce pressure to register COSE parameters if more metadata needs to be added that is not necessarily related to the COSE layer but rather the interaction with inclusion proofs / receipts.

[TODO] Yet another alternative may be to add a single extendable SCITT header parameter that acts as an extendable bucket for anything related to SCITT Merkle Trees and their associated deployments, a bit like CWT payloads. For example, where would hardware attestations go if those were to be included?

# Merkle Tree Leaves

The content of a leaf is defined as the concatenation of an implementation-specific prefix byte stream and a CBOR-encoded LeafEntry structure:

~~~
LeafBytes = prefix + LeafEntryBytes
~~~

LeafEntryBytes is created by encoding LeafEntry to a byte string, using the encoding described in {{deterministic-cbor}}.

LeafEntry is a structure that contains the entry type and type-specific data:

~~~ cddl
LeafEntry = [
    type: LeafEntryType,
    data: LeafEntryData
]
LeafEntryType = int
LeafEntryData = any
~~~

Comparison: See {{Section 4.5 of RFC9162}} where leaves are represented as a DER-encoded structure containing type, and type-dependent data.

A specification of a leaf entry type must define the following:

- The value of LeafEntryType
- The type of LeafEntryData
- The type of LeafReceiptData, which defines what to include in a receipt (see {{receipts}})
- A procedure to re-construct the value of LeafEntryData

~~~ cddl
LeafReceiptData = any
~~~

## COSE_Sign1 Countersign type

LeafEntryType value: 1

LeafEntryData type: Countersign_structure

LeafReceiptData type: SignerData

~~~ cddl
Countersign_structure = [
    context: "CounterSignatureV2",
    body_protected: empty_or_serialized_map,
    sign_protected: empty_or_serialized_map,
    external_aad: bstr,  ; always empty
    payload: bstr,
    other_fields: [
        signature: bstr
    ]
]

SignerData = [
    sign_protected: empty_or_serialized_map
]
~~~

body_protected, payload, and signature are of the target COSE_Sign1 message. sign_protected is from the signer within the DerivationInfo structure. external_aad is externally supplied data from the application encoded in a bstr. If this field is not supplied, it defaults to a zero-length byte string.

Comparison: Countersign_structure is identical to COSE V2 countersigning.

Procedure for reconstruction of LeafEntryData:

1. Let Target be the COSE_Sign1 message that corresponds to the countersignature. Different environments will have different mechanisms to achieve this. One obvious mechanism is to embed the receipt in the unprotected header of Target. Another mechanism may be to store both artifacts separately and use a naming convention, database, or other method to link both together.

2. Extract body_protected, payload, and signature from Target.

3. Create a Countersign_structure using the extracted fields from Target, and sign_protected from the receipt data. This is LeafEntryData.

# Receipts      {#receipts}

A Receipt is an inclusion proof backed by a signed tree root. The Receipt structure is a CBOR array. The fields of the array in order are:

- signed_root: The signed root (COSE_Sign1).

- inclusion_proof: The Merkle proof for the leaf as an array of [left, digest] pairs.

- leaf: Information about the leaf that is needed to reconstruct LeafEntryData.

The CDDL fragment that represents the above text for SCITT_Receipt follows.

~~~ cddl
Receipt = [
    signed_root: SignedRoot,
    inclusion_proof: [+ ProofElement],
    leaf: LeafInfo
]

LeafInfo = [
    prefix: bstr,
    type: LeafEntryType,
    data: LeafReceiptData
]

ProofElement = [
    left: bool
    hash: bstr
]
~~~

## Verification Process

The following steps must be followed to verify a Receipt:

1. Verify the signature of the signed root using standard COSE signature validation.

2. Compute LeafEntryData according to the LeafEntryType.

3. Construct a LeafEntry structure and fill it with LeafEntryType and LeafEntryData.

4. Compute LeafBytes as concatenation of prefix and LeafEntryBytes, where LeafEntryBytes is created by encoding LeafEntry to a byte string, using the encoding described in {{deterministic-cbor}}.

        LeafBytes := prefix + LeafEntryBytes

5. Compute the leaf digest from LeafBytes using the Merkle Tree Hash Algorithm, either found in the protected header of the signed tree root or known by prior agreement.

        LeafDigest := H(LeafBytes)

6. Compute root digest from leaf digest and Merkle proof

        h := LeafDigest
        for [left, hash] in proof:
            h := H(hash + h) if left
                 H(h + hash) else
        root := h

7. Verify that root matches the payload of the signed root message.

## SCITT Countersign Receipt

A SCITT Countersign Receipt is a receipt where the leaf entry type is 1 (COSE_Sign1 Countersign type).

~~~
SCITT_Countersign_Receipt = Receipt
~~~

## Recommended signing and hash algorithms

The following signing and hash algorithms are recommended for secure use. Implementations that verify receipts MAY reject other algorithms.

COSE signing algorithms:

- -7 (ES256)
- -35 (ES384)
- -8 (EdDSA)

Merkle Tree hash algorithms:

- 1 (sha-256)
- 7 (sha-384)

# CBOR Encoding Restrictions    {#deterministic-cbor}

In order to always regenerate the same byte string for the "to be signed" and "to be hashed" values, the core deterministic encoding rules defined in {{Section 4.2.1 of RFC8949}} MUST be used.

# Privacy Considerations

Privacy Considerations

# Security Considerations

Security Considerations

# IANA Considerations

## COSE header parameters

### SCITT Merkle Tree hash algorithm parameter

IANA is requested to register the new COSE Header parameter defined below in the "COSE Header Parameters" registry. The new parameter is used within the protected header to identify the Merkle Tree hash algorithm in a signed Merkle tree root message.

Name: SCITT Merkle Tree Hash Algorithm

Label: TBD

Value Type: int

Value Registry: {{IANA.named-information}}

Description: The Merkle Tree Hash Algorithm used in a signed Merkle tree root message.

### SCITT Countersign Receipts parameter

IANA is requested to register the new COSE Header parameter defined below in the "COSE Header Parameters" registry. The new parameter is used for embedding one or more SCITT Countersign Receipts in the unprotected header of a COSE message.

Name: SCITT Countersign receipt

Label: TBD

Value Type: SCITT_Countersign_Receipt / \[+ SCITT_Countersign_Receipt\]

Description: A SCITT Countersign Receipt to be embedded in the unprotected header of the countersigned COSE_Sign1 message.

--- back

