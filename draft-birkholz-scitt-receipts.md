---
title: Countersigning COSE Envelopes in Transparency Services
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
- ins: A. Delignat-Lavaud
  name: Antoine Delignat-Lavaud
  organization: Microsoft
  email: antdl@microsoft.com
  country: UK
- ins: C. Fournet
  name: Cedric Fournet
  organization: Microsoft
  email: fournet@microsoft.com
  country: UK

normative:
  RFC8949:
  RFC9162:
  RFC6234:
  RFC8032:
  RFC6979:

informative:
  I-D.ietf-cose-countersign:
  I-D.birkholz-scitt-architecture:
  CCF_Merkle_Tree:
    target: https://microsoft.github.io/CCF/main/architecture/merkle_tree.html
    title: CCF - Merkle Tree
    author:
      ins: Microsoft Research
  DID:
    target: https://www.w3.org/TR/did-core/
    title: W3C Decentralized Identifiers

--- abstract

A transparent and authentic Transparency Service in support of a supply chain's integrity, transparency, and trust requires all peers that contribute to the Registry operations to be trustworthy and authentic. In this document, a COSE signature algorithm and COSE profile are specified that enable trust assertions on Merkle-tree based operations for global supply chain registries. A generic procedure for producing payloads to be signed and validated is defined and leverages solutions and principles from the Concise Signing and Encryption (COSE) space.

TODO rewrite abstract, main points are:
- use standard COSE countersignatures for TS receipts
- support specific transparency service types through existing and new signature algorithms
- define a new algorithm for CCF-based transparency services
- rely on COSE header and profiling for key identification and discovery

--- middle

# Introduction

We adopt the terminology of the Supply Chain Integrity, Transparency, and Trust (SCITT) architecture document (An Architecture for Trustworthy and Transparent Digital Supply Chains, see {{I-D.birkholz-scitt-architecture}}): Transparency Service, Registry, Envelope, Receipt, and Verifier.

This document defines Receipts issued by Transparency Services as a profile of COSE_Sign1 countersignatures ({{I-D.ietf-cose-countersign}}). Different Transparency Service types may rely on different authenticated data structures and processes. Those are supported through existing and new signature algorithms. This document defines a first new signature algorithm for CCF-compatible Transparency Services.

## Requirements Notation

{::boilerplate bcp14-tagged}

{: #mybody}

# COSE_Sign1 Countersignature Profile

A receipt acknowledges the registration of a COSE_Sign1 message in a Transparency Service and is represented as a COSE_Countersignature structure following {{I-D.ietf-cose-countersign}}. This section defines the contents of the COSE headers of the countersigner (the Transparency Service) and how they can be used to identify and/or discover the public key needed for signature verification and establish the identity of the countersigner needed for evaluation of further policies in verifiers. It also provides methods for carrying the countersignature either within or outside the countersigned COSE_Sign1 envelope.

For reference, the CDDL of the COSE_Countersignature structure is repeated here:

~~~ cddl
COSE_Countersignature = COSE_Signature
COSE_Signature = [
    protected : empty_or_serialized_map,
    unprotected : header_map
    signature : bstr
]
header_map = {
    * label => values
}
empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
label = int / tstr
values = any
~~~

## Header parameters

The following parameters MUST always be included in the protected header:
- alg (label: 1): The signing algorithm that was used.
- Profile (label: TBD, temporary: -67550): COSE profile as CBOR array of name and version: ["SCITT-Receipt", 1].
- Issued At (label: TBD, temporary: -67570): The time at which the countersignature was issued as the number of seconds from 1970-01-01T00:00:00Z UTC, ignoring leap seconds, represented as CBOR integer. [TODO] should this be registered outside of SCITT for wider re-use?

If the Transparency Service uses {{DID}} (DIDs) to identify itself as issuer of the countersignature, then the following parameters MUST be included in the protected header:
- Issuer (label: TBD, temporary: -67560): The DID of the countersigner as CBOR tstr. Example: "did:example:12345".
- kid (label: 4): The DID URL relative to the Issuer DID that identifies the verification method (public key) within the DID document of the countersigner, UTF-8 encoded within a bstr (Note: this is not a CBOR tstr!). Example: b"#abcde".

To obtain the public key needed for signature verification when using a DID as identifier, verifiers carry out DID resolution as described in {{DID}} using the Issuer parameter as DID, followed by key selection using the UTF-8 decoded kid parameter.

If the Transparency Service uses a unique but opaque identifier to identify itself, then the following parameters MUST be included in the protected header:
- kid (label: 4): The opaque text identifier of the Transparency Service, UTF-8 encoded within a bstr (Note: this is not a tstr!). Example: b"893u28hj89few9hn98dfs89".

To obtain the public key needed for signature verification with opaque identifiers, verifiers look-up the key in their local trust store that matches the given UTF-8 decoded kid. Note that this variant mirrors the Log ID concept in Certificate Transparency logs (see RFC 9162).

## Carrying receipts

This document defines two methods to carry receipts:

- Embedded in the header of the countersigned envelope
- Separated outside the countersigned envelope

{{I-D.ietf-cose-countersign}} defines the header parameter to embed a receipt as a standard countersignature in the unprotected header of the countersigned envelope. Note that the parameter may already exist in the envelope and existing countersignatures should not be removed. A receipt can be distinguished from other countersignatures by inspecting the Profile header parameter. Note that embedded countersignatures are not tagged since the header parameter uniquely identifies the type of the countersignature.

A receipt can also be carried outside of the countersigned envelope. In this case, the receipt should be tagged as COSE_Countersignature_Tagged (see {{I-D.ietf-cose-countersign}}) to aid identification and versioning.

# Signature scheme for CCF-Compatible Transparency Services

This section defines the Transparency Service signature scheme SCITT-CCF. The scheme is based on signing the root of a binary Merkle tree over the sequence of all Transparency Service claims, as implemented in the Confidential Consortium Framework (see {{CCF_Merkle_Tree}}). It can be considered a meta-scheme as it relies on existing signature schemes like ECDsa.

## COSE Algorithms

Each algorithm defined for the scheme determines both the base signing algorithm and the Merkle tree hash algorithm. The following table lists the initial algorithms:

| kty | alg             | Base alg | Merkle hash alg |
|-----|-----------------|----------|-----------------|
| EC  | SCITT-CCF-ES256 | ES256    | SHA-256         |
| EC  | SCITT-CCF-ES384 | ES384    | SHA-384         |
| EC  | SCITT-CCF-ES512 | ES512    | SHA-512         |

## Cryptographic Components

Note: This section is adapted from {{Section 2.1 of RFC9162}}, which provides additional discussion of Merkle trees.

### Binary Merkle Trees {#merkle-tree-def}

The input of the Merkle Tree Hash (MTH) function is a list of n bytestrings, written D_n = \{d\[0\], d\[1\], ..., d\[n-1\]\}. The output is a single HASH_SIZE bytestring, also called the tree root hash.

This function is defined as follows:

The hash of an empty list is the hash of an empty string:

~~~
MTH({}) = HASH().
~~~

The hash of a list with one entry (also known as a leaf hash) is:

~~~
MTH({d[0]}) = HASH(d[0]).
~~~

For n > 1, let k be the largest power of two smaller than n (i.e., k < n <= 2k). The Merkle Tree Hash of an n-element list D_n is then defined recursively as:

~~~
MTH(D_n) = HASH(MTH(D[0:k]) || MTH(D[k:n])),
~~~

where:

- \|\| denotes concatenation
- : denotes concatenation of lists
- D\[k1:k2\] = D'_(k2-k1) denotes the list \{d'\[0\] = d\[k1\], d'\[1\] = d\[k1+1\], ..., d'\[k2-k1-1\] = d\[k2-1\]\} of length (k2 - k1).

### Merkle Inclusion Proofs

A Merkle inclusion proof for a leaf in a Merkle Tree is the shortest list of intermediate hash values required to re-compute the tree root hash
from the digest of the leaf bytestring. Each node in the tree is either a leaf node or is computed from the two nodes immediately below it (i.e., towards the leaves). At each step up the tree (towards the root), a node from the inclusion proof is combined with the node computed so far. In other words, the inclusion proof consists of the list of missing nodes required to compute the nodes leading from a leaf to the root of the tree. If the root computed from the inclusion proof matches the true root, then the inclusion proof proves that the leaf exists in the tree.

#### Verifying an Inclusion Proof

When a client has received an inclusion proof and wishes to verify inclusion of a leaf_hash for a given root_hash, the following algorithm may be used to prove the hash was included in the root_hash:

    recompute_root(leaf_hash, proof):
      h := leaf_hash
      for [left, hash] in proof:
        if left
          h := HASH(hash || h)
        else
          h := HASH(h || hash)
      return h

#### Generating an Inclusion Proof

Given the MTH input D_n = \{d\[0\], d\[1\], ..., d\[n-1\]\} and an index i < n in this list,
run the MTH algorithm and record the position and value of every intermediate hash
concatenated and hashed first with the digest of the leaf, then with the resulting intermediate hash value. (Most implementations instead record all intermediate hash computations, so that they can produce all inclusion proofs for a given tree by table lookups.)

## Encoding To-Be-Signed into Tree Leaves

This section describes the encoding of To-Be-Signed (TBS) and auxiliary ledger entries
into the leaf bytestrings passed as input to the Merkle Tree function.

Each bytestring is computed from three inputs:

- `internal_hash`: a string of HASH_SIZE bytes;
- `internal_data`: a string of at most 1024 bytes; and
- `data_hash`: either the HASH of the TBS bytes, or a bytestring of size HASH_SIZE filled with zeroes for auxiliary ledger entries.

as the concatenation of three hashes:

~~~
LeafBytes = internal_hash || HASH(internal_data) || data_hash
~~~

This ensures that leaf bytestrings are always distinct from the inputs of the intermediate computations in MTH, which always consist of two hashes, and also that leaf bytestrings for TBS and for auxiliary ledger entries are always distinct.

The `internal_hash` and `internal_data` bytestrings are internal to the CCF implementation. Similarly, the auxiliary ledger entries are internal to CCF. They are opaque to signature Verifiers, but they commit the TS to the whole ledger contents and may be used for additional, CCF-specific auditing.

## Signature Encoding

The signature bytes are the CBOR-encoding of a CBOR array SCITT_CCF_Signature. The items of the array in order are:

- `root_signature`: the signature over the Merkle tree root as bstr.

- `node_certificate`: a DER-encoded X.509 certificate for the public key for signature verification.
  This certificate MUST be a valid CCF node certificate
for the service; in particular, it MUST be signed by the key passed to the SCITT-CCF signature algorithm.

- `inclusion_proof`: the intermediate hashes to recompute the signed root of the Merkle tree from the leaf digest of the envelope.
  - The array MUST have at most 64 items.
  - The inclusion proof structure is an array of \[left, hash\] pairs where `left` indicates the ordering of digests for the intermediate hash compution. The hash MUST be a bytestring of length `HASH_SIZE`.

- `leaf_info`: auxiliary inputs to recompute the leaf digest included in the Merkle tree: the internal hash and the internal data.
  - `internal_hash` MUST be a bytestring of length `HASH_SIZE`;
  - `internal_data` MUST be a bytestring of length less than 1024.

The inclusion of an additional, short-lived certificate endorsed by the TS enables flexibility in its distributed implementation, and may support additional CCF-specific auditing.

The CDDL fragment that represents the above text follows.

~~~ cddl
SCITT_CCF_Signature = [
    root_signature: bstr,
    node_certificate: bstr,
    inclusion_proof: [+ ProofElement],
    leaf_info: LeafInfo
]

ProofElement = [
    left: bool
    hash: bstr
]

LeafInfo = [
    internal_hash: bstr,
    internal_data: bstr
]
~~~

## Signature Verification

Given the public key, the TBS bytes, and the signature bytes, the following steps must be followed to verify the signature.

1. Decode the signature bytes as the CBOR structure SCITT_CCF_Signature.

2. Compute `LeafBytes` as the bytestring concatenation of internal_hash, the hash of internal_data, and the hash of the TBS, using the Merkle tree hash algorithm.

        LeafBytes := internal_hash || HASH(internal_data) || HASH(TBS)

3. Compute the leaf digest.

        LeafHash := HASH(LeafBytes)

4. Compute the root hash from the leaf hash and the Merkle proof using the Merkle Tree Hash Algorithm:

        root := recompute_root(LeafHash, inclusion_proof)

5. Verify that the certificate in node_certificate is signed by the public key passed to the signature algorithm. [TODO]: ignore the validity period of the certificate for now. Not sure yet how that would work.

6. Verify that `root_signature` is a valid signature value of the root hash, using the public key in node_certificate and the base signature algorithm.

## Signature Generation

This document provides a reference algorithm for producing valid signatures,
but it omits any discussion of TS registration policy and any CCF-specific implementation details.

The algorithm takes as input a list of entries to be jointly signed, each entry consisting of `internal_hash`, `internal_data`, and an optional TBS value.
(This optional item reflects that a CCF ledger records both TBS-type and auxiliary entries.)

1. For each item in the list, compute `LeafBytes` as the bytestring concatenation of the internal hash, the hash of internal data and, if TBS is present, the hash of the TBS bytes, otherwise a HASH_SIZE bytestring of zeroes.

2. Compute the tree root hash by applying MTH to the resulting list of leaf bytestrings,
  keeping the results for all intermediate HASH values.

3. Select a valid `node_certificate` and compute a `root_signature` of the root of the tree with the corresponding signing key.

4. For each TBS-type entry provided in the input,

    - Collect an `inclusion_proof` by selecting intermediate hash values, as described above.

    - Produce the SCITT_CCF_Signature structure using this `inclusion_proof`, the fixed `node_certificate` and `root_signature`, and the bytestrings `internal_hash` and `internal_data` provided with each entry.

    - CBOR-encode the SCITT_CCF_Signature structure as the resulting signature bytes.


# CBOR Encoding Restrictions    {#deterministic-cbor}

In order to always regenerate the same byte string for the "to be signed" and "to be hashed" values, the core deterministic encoding rules defined in {{Section 4.2.1 of RFC8949}} MUST be used for all their CBOR structures.

# Privacy Considerations

TBD

# Security Considerations

TBD

# IANA Considerations

## Additions to Existing Registries

### New Entries to the COSE Algorithms Registry

IANA is requested to register the new COSE algorithms defined below in the "COSE Algorithms" registry.

#### SCITT-CCF-ES256

Name: SCITT-CCF-ES256

Value: TBD (temporary: -65656)

Description: SCITT-CCF signature using ES256

Capabilities: [kty]

Change Controller: TBD

Reference: TBD

Recommended: Yes

[TODO] Should recommended be yes or no? Who is the recommendation for?

[TODO] add similar entries for SCITT-CCF-ES384 and SCITT-CCF-ES512

### New Entries to the COSE Header Parameters Registry

IANA is requested to register the new COSE Header parameters defined below in the "COSE Header Parameters" registry.

#### Profile

Name: Profile

Label: TBD (temporary: -67550)

Value Type: array [name: tstr, version: int]

Description: The COSE profile that is used.

#### Issuer

Name: Issuer

Label: TBD (temporary: -67560)

Value Type: tstr

Description: The issuer of the (counter-)signature.

#### Issued At

Name: Issued At

Label: TBD (temporary: -67570)

Value Type: uint

Description: The time at which the signature was issued as the number of seconds from 1970-01-01T00:00:00Z UTC, ignoring leap seconds.

--- back

