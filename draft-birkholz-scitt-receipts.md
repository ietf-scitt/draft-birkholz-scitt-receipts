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

--- abstract

A transparent and authentic ledger service in support of a supply chain's integrity, transparency, and trust requires all peers that contribute to the ledgers operations to be trustworthy and authentic. In this document, a countersigning variant is specified that enables trust assertions on Merkle-tree based operations for global supply chain ledgers. A generic procedure for producing payloads to be signed and validated is defined and leverages solutions and principles from the Concise Signing and Encryption (COSE) space.

--- middle

# Introduction

This document defines a method for issuing and verifying countersignatures on COSE_Sign1 messages included in an authenticated data structure such as a Merkle Tree.

We adopt the terminology of An Architecture for Trustworthy and Transparent Digital Supply Chains (see {{I-D.birkholz-scitt-architecture}}) for Claim, Envelope, Transparency Service, Ledger, Receipt, and Verifier.

> [TODO] Do we need to explain or introduce them here? We may also define Tree (our shorthand for authenticated data structure), Root (a succinct commitment to the Tree, e.g., a hand) and use Issuer instead of TS.

From the Verifier's viewpoint, a Receipt is similar to a countersignature V2 on a single signed message: it is a universally-verifiable cryptographic proof of endorsement of the signed envelope by the countersigner.

Compared with countersignatures on single COSE envelopes,

- Receipts countersign the envelope in context, providing authentication both of the envelope and of its logical position in the authenticated data structure.
- Receipts are proof of commitment to the whole contents of the data structure, even if the Verifier knows only some of its contents.
- Receipts can be issued in bulk, using a single public-key signature for issuing a large number of Receipts.

## Requirements Notation

{::boilerplate bcp14-tagged}

{: #mybody}

# Common Parameters

Verifiers are configured by a collection of parameters
to identify a Transparency Service and verify its Receipts.
These parameters MUST be fixed for the lifetime of the Transparency Service
and securely communicated to all Verifiers.

At minimum, these parameters include:

- a Service identifier: An opaque identifier (e.g. UUID) that uniquely identifies the service and can be used to securely retrieve all other Service parameters.

- The Tree algorithm used for issuing receipts, and its additional parameters, if any. This document creates a registry (see {{tree-alg-registry}}) and describes an initial set of tree algorithms.

  > [TODO] The architecture also has fixed TS registration policies.

# Generic Receipt Structure

A Receipt represents a countersignature issued by a Transparency Service.

The Receipt structure is a CBOR array with two items, in order:

- `service_id`: The service identifier as tstr.

- `contents`: The proof as a CBOR structure determined by the tree algorithm.

~~~ cddl
Receipt = [
  service_id: tstr,
  contents: any
]
~~~

Each tree algorithm MUST define its contents type and procedures for issuing and verifying a receipt.

# COSE_Sign1 Countersigning    {#cose_sign1_countersign}

While the tree algorithms may differ in the way they aggregate multiple envelopes to compute a digest to be signed by the TS,
they all share the same representation of the individual envelopes to be countersigned (intuitively, their leaves).

This document uses the principles and structure definitions
of COSE_Sign1 countersigning V2 ({{I-D.ietf-cose-countersign}}).
Each envelope is authenticated using a `Countersign_structure` array, recalled below.

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
~~~

The `body_protected`, `payload`, and `signature` fields are copied from the COSE_Sign1 message being countersigned.

The `sign_protected` field is provided by the TS, see {{countersign_headers}} below. This field
is included in the Receipt contents to enable the Verifier to re-construct `Countersign_structure`, as specified by the tree algorithm.

By convention, the TS always provides an empty `external_aad`: a zero-length bytestring.

Procedure for reconstruction of Countersign_structure:

1. Let Target be the COSE_Sign1 message that corresponds to the countersignature. Different environments will have different mechanisms to achieve this. One obvious mechanism is to embed the Receipt in the unprotected header of Target. Another mechanism may be to store both artifacts separately and use a naming convention, database, or other method to link both together.

2. Extract body_protected, payload, and signature from Target.

3. Create a Countersign_structure using the extracted fields from Target, and sign_protected from the Receipt contents.

## Countersigner Header Parameters    {#countersign_headers}

The following parameters MUST be included in the protected header of the countersigner (sign_protected in {{cose_sign1_countersign}}):

- Issued At (label: TBD): The time at which the countersignature was issued as the number of seconds from 1970-01-01T00:00:00Z UTC, ignoring leap seconds.

# CCF 2 Tree Algorithm

The CCF 2 tree algorithm specifies an algorithm based on a binary Merkle tree over the sequence of all ledger entries, as implemented in the CCF version 2 framework (see {{CCF_Merkle_Tree}}).

## Additional Parameters        {#parameters}

The algorithm requires that the TS define
additional parameters:

- Hash Algorithm: The hash algorithm used in its Merkle Tree (see {{hash-alg-registry}}).

- Signature Algorithm: The signature algorithm used (see {{sig-alg-registry}}).

- Service Certificate: The self-signed X.509 certificate used as trust anchor to verify signatures generated by the transparency service using the Signature Algorithm.

All definitions in this section use the hash algorithm set in the TS parameters (see Section {{parameters}}). We write HASH to refer to this algorithm, and HASH_SIZE for the fixed length of its output in bytes.

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

## Encoding Signed Envelopes into Tree Leaves

This section describes the encoding of signed envelopes and auxiliary ledger entries
into the leaf bytestrings passed as input to the Merkle Tree function.

Each bytestring is computed from three inputs:

- `internal_hash`: a string of HASH_SIZE bytes;
- `internal_data`: a string of at most 1024 bytes; and
- `data_hash`: either the HASH of the CBOR-encoded Countersign_structure of the signed envelope, using the CBOR encoding described in {{deterministic-cbor}}, or a bytestring of size HASH_SIZE filled with zeroes for auxiliary ledger entries.

as the concatenation of three hashes:

~~~
LeafBytes = internal_hash || HASH(internal_data) || data_hash
~~~

This ensures that leaf bytestrings are always distinct from the inputs of the intermediate computations in MTH, which always consist of two hashes, and also that leaf bytestrings for signed envelopes and for auxiliary ledger entries are always distinct.

The `internal_hash` and `internal_data` bytestrings are internal to the CCF implementation. Similarly, the auxiliary ledger entries are internal to CCF. They are opaque to receipt Verifiers, but they commit the TS to the whole ledger contents and may be used for additional, CCF-specific auditing.

## Receipt Contents Structure {#ReceiptContents}

The Receipt contents structure is a CBOR array. The items of the array in order are:

- `signature`: the signature over the Merkle tree root as bstr.

- `node_certificate`: a DER-encoded X.509 certificate for the public key for signature verification.
  This certificate MUST be a valid CCF node certificate
for the service; in particular, it MUST form a valid X.509 certificate chain with the service certificate.

- `inclusion_proof`: the intermediate hashes to recompute the signed root of the Merkle tree from the leaf digest of the envelope.
  - The array MUST have at most 64 items.
  - The inclusion proof structure is an array of \[left, hash\] pairs where `left` indicates the ordering of digests for the intermediate hash compution. The hash MUST be a bytestring of length `HASH_SIZE`.

- `leaf_info`: auxiliary inputs to recompute the leaf digest included in the Merkle tree: the internal hash, the internal data, and the protected header of the
countersigner.
  - `internal_hash` MUST be a bytestring of length `HASH_SIZE`;
  - `internal_data` MUST be a bytestring of length less than 1024.

The inclusion of an additional, short-lived certificate endorsed by the TS enables flexibility in its distributed implementation, and may support additional CCF-specific auditing.

The CDDL fragment that represents the above text follows.

~~~ cddl
ReceiptContents = [
    signature: bstr,
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
    internal_data: bstr,
    sign_protected: empty_or_serialized_map
]
~~~

## Receipt Verification

Given the TS parameters, a signed envelope, and a Receipt for it,
the following steps must be followed to verify this Receipt.

1. Verify that the Receipt Content structure is well-formed, as described in {{ReceiptContents}}.

2. Construct a `Countersign_structure` as described in {{cose_sign1_countersign}}, using `sign_protected` from the `leaf_info` field of the receipt contents.

3. Compute `LeafBytes` as the bytestring concatenation of the internal hash, the hash of internal data, and the hash of the CBOR-encoding of `Countersign_structure`, using the CBOR encoding described in {{deterministic-cbor}}.

        LeafBytes := internal_hash || HASH(internal_data) || HASH(cbor(Countersign_structure))

4. Compute the leaf digest.

        LeafHash := HASH(LeafBytes)

5. Compute the root hash from the leaf hash and the Merkle proof using the Merkle Tree Hash Algorithm found in the service's parameters (see {{parameters}}):

        root := recompute_root(LeafHash, inclusion_proof)

6. Verify the certificate chain established by the node certificate embedded in the receipt and the fixed service certificate in the TS parameters (see {{parameters}}) using the Issued At time from `sign_protected` to verify the validity periods of the certificates. The chain MUST enable the use of the public key in the receipt certificate for signature verification with the Signature Algorithm of the TS parameters.

7. Verify that `signature` is a valid signature value of the root hash, using the public key of the receipt certificate and the Signature Algorithm of the TS parameters.

The Verifier SHOULD apply additional checks before accepting the countersigned envelope as valid, based on its protected headers and payload.

## Receipt Generation

This document provides a reference algorithm for producing valid receipts,
but it omits any discussion of TS registration policy and any CCF-specific implementation details.

The algorithm takes as input a list of entries to be jointly countersigned, each entry consisting of `internal_hash`, `internal_data`, and an optional signed envelope.
(This optional item reflects that a CCF ledger records both signed envelopes and auxiliary entries.)

1. For each signed envelope, compute the `Countersign_structure` as described in {{cose_sign1_countersign}}.

2. For each item in the list, compute `LeafBytes` as the bytestring concatenation of the internal hash, the hash of internal data and, if the envelope is present, the hash of the CBOR-encoding of `Countersign_structure`, using the CBOR encoding described in {{deterministic-cbor}}, otherwise a HASH_SIZE bytestring of zeroes.

3. Compute the tree root hash by applying MTH to the resulting list of leaf bytestrings,
  keeping the results for all intermediate HASH values.

4. Select a valid `node_certificate` and compute a `signature` of the root of the tree with the corresponding signing key.

4. For each signed envelope provided in the input,

    - Collect an `inclusion_proof` by selecting intermediate hash values, as described above.

    - Produce the receipt contents using this `inclusion_proof`, the fixed `node_certificate` and `signature`, and the bytestrings `internal_hash` and `internal_data` provided with the envelope.

    - Produce the receipt using the Service Identifier and this receipt contents.

# CBOR Encoding Restrictions    {#deterministic-cbor}

In order to always regenerate the same byte string for the "to be signed" and "to be hashed" values, the core deterministic encoding rules defined in {{Section 4.2.1 of RFC8949}} MUST be used for all their CBOR structures.

# Privacy Considerations

TBD

# Security Considerations

TBD

# IANA Considerations

## Additions to Existing Registries

### New Entries to the COSE Header Parameters Registry

IANA is requested to register the new COSE Header parameters defined below in the "COSE Header Parameters" registry.

#### COSE_Sign1 Countersign receipt

Name: COSE_Sign1 Countersign receipt

Label: TBD

Value Type: \[+ Receipt\]

Description: One or more COSE_Sign1 Countersign Receipts to be embedded in the unprotected header of the countersigned COSE_Sign1 message.

#### Issued At

Name: Issued At

Label: TBD

Value Type: uint

Description: The time at which the signature was issued as the number of seconds from 1970-01-01T00:00:00Z UTC, ignoring leap seconds.

## New SCITT-Related Registries

IANA is asked to add a new registry "TBD" to the list that appears at https://www.iana.org/assignments/.

The rest of this section defines the subregistries that are to be created within the new "TBD" registry.

### Tree Algorithms    {#tree-alg-registry}

IANA is asked to establish a registry of tree algorithm identifiers, named "Tree Algorithms", with the following registration procedures: TBD

The "Tree Algorithms" registry initially consists of:

| Identifier | Tree Algorithm       | Reference     |
| CCF-2      | CCF 2 tree algorithm | This document |
{: title="Initial content of Tree Algorithms registry"}

The designated expert(s) should ensure that the proposed algorithm has a public specification and is suitable for use as [TBD].

### Hash Algorithms    {#hash-alg-registry}

IANA is asked to establish a registry of hash algorithm identifiers, named "Hash Algorithms", with the following registration procedures: TBD

The "Hash Algorithms" registry initially consists of:

| Identifier | Hash Algorithm | Reference   |
| SHA-256    | SHA-256        | {{RFC6234}} |
{: title="Initial content of Hash Algorithms registry"}

The designated expert(s) should ensure that the proposed algorithm has a public specification and is suitable for use as a cryptographic hash algorithm with no known preimage or collision attacks. These attacks can damage the integrity of the ledger.

### Signature Algorithms     {#sig-alg-registry}

IANA is asked to establish a registry of signature algorithm identifiers, named "Signature Algorithms", with the following registration procedures: TBD

The "Signature Algorithms" registry initially consists of:

| Identifier | Signature Algorithm | Reference |
| ES256      | Deterministic ECDSA (NIST P-256) with HMAC-SHA256 | {{RFC6979}} |
| ED25519    | Ed25519 (PureEdDSA with the edwards25519 curve)  | {{RFC8032}} |
{: title="Initial content of Signature Algorithms registry"}

The designated expert(s) should ensure that the proposed algorithm has a public specification and is suitable for use as a cryptographic signature algorithm.

--- back

