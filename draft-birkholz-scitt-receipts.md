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

--- abstract

A transparent and authentic ledger service in support of a supply chain's integrity, transparency, and trust requires all peers that contribute to the ledgers operations to be trustworthy and authentic. In this document, a countersigning variant is specified that enables trust assertions on merkle-tree based operations for global supply chain ledgers. A generic procedure how to produce payloads for signing and validation is defined and leverages solutions and principles from the Concise Signing and Encryption (COSE) space.

--- middle
---
# Introduction

This document defines a method for issuing and verifying countersignatures on COSE_Sign1 messages included in an authenticated data structure such as a Merkle Tree.

We adopt the terminology of [architecture](pointer) for Claim, Envelope, Transparency Service, Ledger, Receipt, and Verifier. 

> Do we need to explain or introduce them here? We may also define Tree (our shorthand for authenticated data structure), Root (a succinct commitment to the Tree, e.g., a hand) and use Issuer instead of TS. 

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

- a Service identifier: An opaque identifier (e.g. UUID) that uniquely identifies the service and all other parameters.

  > is it sufficient? why putting it in every receipt then? What are those other parameters? I was expecting a public key or a certificate. 

- The Tree algorithm used for issuing receipts, and their additional global parameters, if any. This document creates a registry (see {{tree-alg-registry}}) and describes an initial set of tree algorithms.

  > The architecture also has fixed TS registration policies. 

# Generic Receipt Structure

A Receipt represents a countersignature issued by a Transparency Service.

The Receipt structure is a CBOR map with two items, in order: 

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

This document uses the principals and structure definitions 
of COSE_Sign1 countersigning V2 ({{I-D.ietf-cose-countersign}}).
Each envelope is authenticated using its `Countersign_structure` map,recalled below.

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

body_protected, payload, and signature are of the target COSE_Sign1 message. sign_protected is from the signer, see {{countersign_headers}}. external_aad is always empty (a zero-length byte string).

The sign_protected field is embedded in the Receipt contents to be able to re-construct Countersign_structure during validation. This is part of the definition of the tree algorithm.

Procedure for reconstruction of Countersign_structure:

1. Let Target be the COSE_Sign1 message that corresponds to the countersignature. Different environments will have different mechanisms to achieve this. One obvious mechanism is to embed the Receipt in the unprotected header of Target. Another mechanism may be to store both artifacts separately and use a naming convention, database, or other method to link both together.

2. Extract body_protected, payload, and signature from Target.

3. Create a Countersign_structure using the extracted fields from Target, and sign_protected from the Receipt contents.

## Countersigner Header Parameters    {#countersign_headers}

The following parameters MUST be included in the protected header of the countersigner (sign_protected in {{cose_sign1_countersign}}):

- Issued At (label: TBD): The time at which the countersignature was issued as the number of seconds from 1970-01-01T00:00:00Z UTC, ignoring leap seconds.

# CCF 2 Tree Algorithm

The CCF 2 tree algorithm documents the algorithm based on a binary Merkle tree over the sequence of all ledger entries that is implemented in the CCF version 2 framework.

> Add pointer to CCF v2? 

## Additional Parameters        {#parameters}

The algorithm requires that the TS define 
additional parameters:

- Hash Algorithm: The hash algorithm used in its Merkle Tree (see {{hash-alg-registry}}).

- Signature Algorithm: The signature algorithm used (see {{sig-alg-registry}}).

- Service Certificate: The X.509 certificate used as trust anchor to verify signatures generated by the transparency service.

The Service Certificate MUST be consistent with the Service identifier and Signature Algorithm.  

> No need to require that it be self-signed, right? 

## Cryptographic Components

### Merkle Trees

See {{Section 2.1 of RFC9162}}.

### Definition of the Merkle Tree    {#merkle-tree-def}

Note: This is a partial copy of {{Section 2.1.1 of RFC9162}}.

The ledger uses a binary Merkle Tree for efficient auditing. The hash algorithm used is one of the service's parameters (see Section {{parameters}}). This document establishes a registry of acceptable hash algorithms (see {{hash-alg-registry}}). Throughout this document, the hash algorithm in use is referred to as HASH and the size of its output in bytes is referred to as HASH_SIZE. The input to the Merkle Tree Hash is a list of data entries; these entries will be hashed to form the leaves of the Merkle Tree. The output is a single HASH_SIZE Merkle Tree Hash. Given an ordered list of n inputs, D_n = \{d\[0\], d\[1\], ..., d\[n-1\]\}, the Merkle Tree Hash (MTH) is thus defined as follows:

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

The Merkle Tree Hash over D_n is also called the tree root hash.

The content of all leaf entries is defined as the concatenation of three byte streams:

1. an internal hash, defined by the implementation and used for binding to data that is not revealed in Receipts,

2. a hash of internal data, defined by the implementation and used for binding to data that is revealed in Receipts, and

3. a hash of data that is well-defined and not implementation-specific.

For all hashes, the Merkle Tree Hash Algorithm found in the service's parameters (see {{parameters}}) is used.

Note that the difference in size between leaves (composed of three hashes) and intermediate tree nodes (two hashes) provides second preimage resistance.

~~~
LeafBytes = internal_hash + HASH(internal_data) + HASH(data)
~~~

### Merkle Inclusion Proofs

Note: This is a copy of {{Section 2.1.3 of RFC9162}}.

A Merkle inclusion proof for a leaf in a Merkle Tree is the shortest list of additional nodes in the Merkle Tree required to compute the Merkle Tree Hash for that tree. Each node in the tree is either a leaf node or is computed from the two nodes immediately below it (i.e., towards the leaves). At each step up the tree (towards the root), a node from the inclusion proof is combined with the node computed so far. In other words, the inclusion proof consists of the list of missing nodes required to compute the nodes leading from a leaf to the root of the tree. If the root computed from the inclusion proof matches the true root, then the inclusion proof proves that the leaf exists in the tree.

#### Generating an Inclusion Proof

Given an ordered list of n inputs to the tree, D_n = \{d\[0\], d\[1\], ..., d\[n-1\]\}, the Merkle inclusion proof PATH(m, D_n) for the (m+1)th input d\[m\], 0 <= m < n, is defined as follows:

[TODO] add pseudo-code to generate array of \[left, hash\] pairs given a list of leaves and a target leaf index

#### Verifying an Inclusion Proof

When a client has received an inclusion proof and wishes to verify inclusion of a leaf_hash for a given root_hash, the following algorithm may be used to prove the hash was included in the root_hash:

~~~
compute_root(leaf_hash, proof):
  h := leaf_hash
  for [left, hash] in proof:
      h := HASH(hash + h) if left
           HASH(h + hash) else
  return h

verify_proof(leaf_hash, root_hash, proof):
  h = compute_root(leaf_hash, proof)
  return h == root_hash
~~~

Note: compute_root is used in Receipt verification where the computed root is validated indirectly by verifying the signature over the root.

### Signing of the tree root

A tree root is signed by signing over the tree root hash bytes using the signature algorithm declared in the service's parameters (see {{parameters}}). For example, the signing payload would be 32 bytes for a SHA-256 tree root hash.

## Countersigning Leaves

The leaves that represent countersignatures have as data the CBOR-encoded Countersign_structure, using the CBOR encoding described in {{deterministic-cbor}}:

~~~
LeafBytes = internal_hash + HASH(internal_data) + HASH(cbor(Countersign_structure))
~~~

## Receipt Contents Structure

The Receipt contents structure is a CBOR array. The fields of the array in order are:

> It is a map, right? 

- `signature`: the signature over the Merkle tree root as bstr.

- `node_certificate`: a DER-encoded X.509 certificate for the public key for signature verification. 
  This certificate MUST be a valid CCF node certificate
for the service; in particular, it MUST form a valid X.509 certificate chain with the service certificate. 

- `inclusion_proof`: the intermediate hashes to recompute the signed root of the Merkle tree from the leaf digest of the envelope. 
  - The array MUST have a number of items less than the binary log of the maximal expected size of the ledger. 
  - The inclusion proof structure is an array of \[left, hash\] pairs where `left` indicates the ordering of digests for the intermediate hash compution. The hash MUST be a bytestring of length `HASH_SIZE`.

- `leaf_info`: auxiliary inputs to recompute the leaf digest included in the Merkle tree: the internal hash, the internal data, and the protected header of the 
countersigner.
  - `internal_hash` MUST be a bytestring of length `HASH_SIZE`
  - `internal_data` MUST be a bytestring of length less than `HASH_SIZE + 32`

The inclusion of an additional, short-lived certificate endorsed by the TS enables flexibility in its distributed implementation, and may support additional CCF-specific auditing. 

The internal values passed in `leaf_info` are opaque to the Verifier described in this document, but they may support additional CCF-specific auditing of the ledger. 

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

## Receipt Generation

The following steps must be followed to generate a Receipt after the tree root has been signed:

1. Let LEAF be the countersigning leaf in the Merkle tree for which a Receipt should be generated.

2. Let ROOT_HASH be the root hash of the Merkle tree that contains LEAF, and SIGNATURE the signature over this root.

3. Compute LEAF_HASH as the hash of LEAF.

4. Generate an inclusion proof from LEAF_HASH to ROOT_HASH.

5. Construct a LeafInfo structure with the internal hash, the internal data, and the protected header parameters of the countersigner.

6. Create a ReceiptContents structure and fill it with SIGNATURE, the node's signing certificate endorsed by the service certificate, the inclusion proof, and the LeafInfo.

7. Create a Receipt structure and fill it with the service identifier and ReceiptContents.

## Receipt Verification

Given the TS parameters, a signed envelope, and a Receipt for it, 
the following steps must be followed to verify this Receipt:

1. Construct a `Countersign_structure` as described in {{cose_sign1_countersign}}, using `sign_protected` from the `leaf_info` field of the receipt contents.

2. Compute LeafBytes as concatenation of the internal hash, the hash of internal data, and the hash of the CBOR-encoding of Countersign_structure, using the Merkle Tree Hash Algorithm found in the service's parameters (see {{parameters}}) and the CBOR encoding described in {{deterministic-cbor}}.

        LeafBytes := internal_hash + HASH(internal_data) + HASH(cbor(Countersign_structure))

4. Compute the leaf hash from LeafBytes using the Merkle Tree Hash Algorithm found in the service's parameters (see {{parameters}}).

        LeafHash := HASH(LeafBytes)

5. Compute the root hash from the leaf hash and the Merkle proof using the Merkle Tree Hash Algorithm found in the service's parameters (see {{parameters}}):

        root := compute_root(LeafHash, proof)

6. Verify the signature with the root hash as payload using the certificate chain established by the node certificate embedded in the receipt and the service certificate part of the service's parameters (see {{parameters}}) using the Issued At time from sign_protected to verify certificate validity periods.

# CBOR Encoding Restrictions    {#deterministic-cbor}

In order to always regenerate the same byte string for the "to be signed" and "to be hashed" values, the core deterministic encoding rules defined in {{Section 4.2.1 of RFC8949}} MUST be used for all their CBOR structures.

# Privacy Considerations

Privacy Considerations

# Security Considerations

Security Considerations

# IANA Considerations

## Additions to Existing Registries

### New Entries to the COSE Header Parameters Registry

IANA is requested to register the new COSE Header parameters defined below in the "COSE Header Parameters" registry.

#### COSE_Sign1 Countersign receipt

Name: COSE_Sign1 Countersign receipt

Label: TBD

Value Type: Receipt / \[+ Receipt\]

Description: A COSE_Sign1 Countersign Receipt to be embedded in the unprotected header of the countersigned COSE_Sign1 message.

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

