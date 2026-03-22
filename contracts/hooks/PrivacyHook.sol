// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";

/// @dev Generic interface for zero-knowledge proof verification.
///      Proof-system agnostic — works with Groth16, PLONK, etc.
interface IZKVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/**
 * @title PrivacyHook
 * @notice Example ERC-8183 hook requiring encrypted envelope submissions.
 *         Providers submit an IPFS CID with ECDH-wrapped AES keys instead
 *         of a plaintext deliverable. The hook enforces envelope structure
 *         and optionally verifies a ZK proof over the encrypted data.
 *
 * USE CASE
 * --------
 * When a job's deliverable should remain confidential between provider,
 * client, and evaluator while the escrow flow stays public. The provider
 * encrypts the deliverable with AES-256-GCM, wraps the AES key per
 * recipient via ECDH, uploads the ciphertext to IPFS, and submits the CID
 * on-chain. The hook validates envelope shape and an optional ZK proof
 * over job-specific constraints on the encrypted data.
 *
 * FLOW (all interactions through core contract → hook callbacks)
 * ----
 *  1. createJob(provider, evaluator, expiredAt, description, hook=this)
 *  2. setBudget(jobId, amount, optParams=abi.encode(zkVerifier, minWrappedKeys))
 *     → _postSetBudget: store privacy config for this jobId (one-time, immutable).
 *     Optionally: abi.encode(zkVerifier, minWrappedKeys, numPublicInputs) for
 *     circuits with more than 2 public inputs.
 *  3. fund(jobId, expectedBudget, "") — normal funding, no hook logic.
 *  4. Off-chain: encrypt deliverable, ECDH-wrap the AES key per recipient,
 *     upload ciphertext to IPFS, optionally generate a ZK proof over
 *     (jobId, CID, …).
 *  5. submit(jobId, cid, optParams=abi.encode(cid, wrappedKeys, zkProof))
 *     → _preSubmit: validate envelope structure, verify ZK proof if required,
 *       store envelope commitment hash.
 *     For numPublicInputs > 2:
 *       optParams=abi.encode(cid, wrappedKeys, zkProof, extraPublicInputs)
 *     → core: set Submitted.
 *     → _postSubmit: emit EncryptedSubmission event for off-chain indexing.
 *  6. complete / reject — normal flow. Commitment is cleared either way.
 *
 * WRAPPED KEY FORMAT (v1, 94 bytes)
 * ---------------------------------
 *   version(1) || ephemeralPub(33 compressed) || iv(12) || authTag(16) || encAESKey(32)
 *
 * TRUST MODEL
 * -----------
 * The hook enforces that submissions are properly structured encrypted
 * envelopes. It does NOT verify encryption correctness (that would require
 * the decryption key). The optional ZK proof is the only on-chain link
 * between encrypted contents and job requirements. Payment flow is
 * unchanged — the hook is pure policy enforcement.
 *
 * KEY PROPERTY: No plaintext or ciphertext ever appears on-chain — the hook
 * operates purely on envelope metadata (CID, wrapped keys) and optional ZK
 * proofs over encrypted contents.
 */
contract PrivacyHook is BaseERC8183Hook {
    struct PrivacyConfig {
        address zkVerifier;      // IZKVerifier address, or address(0) if no ZK required
        uint8 minWrappedKeys;    // minimum wrapped keys required (e.g. 2 = client + evaluator)
        uint8 numPublicInputs;   // number of ZK public inputs (default 2: jobId + cid)
        bool configured;         // distinguishes "not set" from "set with defaults"
    }

    uint256 public constant MAX_WRAPPED_KEYS = 50;

    /// @dev Wrapped key format version byte.
    uint8 public constant WRAPPED_KEY_VERSION = 0x01;
    /// @dev Expected length of a v1 wrapped key: version(1) + ephemeralPub(33) + iv(12) + authTag(16) + encAESKey(32) = 94
    uint256 public constant WRAPPED_KEY_V1_LENGTH = 94;

    mapping(uint256 => PrivacyConfig) public privacyConfigs;
    mapping(uint256 => bytes32) public envelopeCommitments;

    error PrivacyNotConfigured();
    error ConfigAlreadySet();
    error CidMismatch();
    error InsufficientWrappedKeys();
    error TooManyWrappedKeys();
    error InvalidWrappedKeyLength();
    error InvalidWrappedKeyVersion();
    error ZKVerificationFailed();
    error EnvelopeAlreadyCommitted();
    error InvalidERC8183Address();
    error InvalidVerifierAddress();
    error InvalidNumPublicInputs();
    error ExtraInputsLengthMismatch();
    error InvalidMinWrappedKeys();

    event PrivacyConfigSet(uint256 indexed jobId, address zkVerifier, uint8 minWrappedKeys, uint8 numPublicInputs);
    event EncryptedSubmission(uint256 indexed jobId, bytes32 indexed cid, bytes32 envelopeHash, bytes[] wrappedKeys);

    constructor(address erc8183Contract_) BaseERC8183Hook(erc8183Contract_) {
        if (erc8183Contract_ == address(0)) revert InvalidERC8183Address();
    }

    // --- Hook callbacks (called by AgenticCommerceHooked via beforeAction/afterAction) ---

    /// @dev Store privacy config from setBudget optParams. Config is immutable once set.
    ///      Backward compatible: 64-byte optParams → (address, uint8) with numPublicInputs=2.
    ///      96-byte optParams → (address, uint8, uint8) with explicit numPublicInputs.
    function _postSetBudget(
        uint256 jobId,
        address,
        address,
        uint256,
        bytes memory optParams
    ) internal override {
        if (optParams.length == 0) return;
        PrivacyConfig storage config = privacyConfigs[jobId];
        if (config.configured) revert ConfigAlreadySet();

        address zkVerifier;
        uint8 minWrappedKeys;
        uint8 numPubInputs;

        if (optParams.length >= 96) {
            (zkVerifier, minWrappedKeys, numPubInputs) = abi.decode(optParams, (address, uint8, uint8));
        } else {
            (zkVerifier, minWrappedKeys) = abi.decode(optParams, (address, uint8));
            numPubInputs = 2; // default: jobId + cid
        }

        if (minWrappedKeys < 1) revert InvalidMinWrappedKeys();
        if (numPubInputs < 2) revert InvalidNumPublicInputs();
        if (zkVerifier != address(0) && zkVerifier.code.length == 0) revert InvalidVerifierAddress();

        privacyConfigs[jobId] = PrivacyConfig({
            zkVerifier: zkVerifier,
            minWrappedKeys: minWrappedKeys,
            numPublicInputs: numPubInputs,
            configured: true
        });
        emit PrivacyConfigSet(jobId, zkVerifier, minWrappedKeys, numPubInputs);
    }

    /// @dev Validate encrypted envelope structure and optional ZK proof.
    function _preSubmit(
        uint256 jobId,
        address,
        bytes32 deliverable,
        bytes memory optParams
    ) internal override {
        PrivacyConfig memory config = privacyConfigs[jobId];
        if (!config.configured) revert PrivacyNotConfigured();
        if (envelopeCommitments[jobId] != bytes32(0)) revert EnvelopeAlreadyCommitted();

        bytes32 cid;
        bytes[] memory wrappedKeys;
        bytes memory zkProof;
        bytes32[] memory extraPublicInputs;

        if (config.numPublicInputs > 2) {
            // Extended format: (bytes32, bytes[], bytes, bytes32[])
            (cid, wrappedKeys, zkProof, extraPublicInputs) =
                abi.decode(optParams, (bytes32, bytes[], bytes, bytes32[]));
        } else {
            // Standard format: (bytes32, bytes[], bytes)
            (cid, wrappedKeys, zkProof) =
                abi.decode(optParams, (bytes32, bytes[], bytes));
        }

        // CID in envelope must match the deliverable hash
        if (cid != deliverable) revert CidMismatch();

        // Validate wrapped keys
        uint256 keyCount = wrappedKeys.length;
        if (keyCount < config.minWrappedKeys) revert InsufficientWrappedKeys();
        if (keyCount > MAX_WRAPPED_KEYS) revert TooManyWrappedKeys();
        for (uint256 i = 0; i < keyCount;) {
            bytes memory key = wrappedKeys[i];
            if (key.length != WRAPPED_KEY_V1_LENGTH) revert InvalidWrappedKeyLength();
            // Read version byte directly from memory (skip length word at offset 0, first data byte at offset 32)
            uint8 version;
            assembly {
                version := byte(0, mload(add(key, 32)))
            }
            if (version != WRAPPED_KEY_VERSION) revert InvalidWrappedKeyVersion();
            unchecked { ++i; }
        }

        // ZK proof verification (if verifier is configured)
        if (config.zkVerifier != address(0)) {
            if (extraPublicInputs.length != uint256(config.numPublicInputs) - 2) revert ExtraInputsLengthMismatch();
            bytes32[] memory publicInputs = new bytes32[](config.numPublicInputs);
            publicInputs[0] = bytes32(jobId);
            publicInputs[1] = cid;
            for (uint256 i = 0; i < extraPublicInputs.length;) {
                publicInputs[2 + i] = extraPublicInputs[i];
                unchecked { ++i; }
            }
            bool valid = IZKVerifier(config.zkVerifier).verify(zkProof, publicInputs);
            if (!valid) revert ZKVerificationFailed();
        }

        // Store commitment hash (includes jobId to prevent cross-job analysis)
        envelopeCommitments[jobId] = keccak256(abi.encode(jobId, cid, wrappedKeys, zkProof));
    }

    /// @dev Emit event for off-chain discoverability.
    function _postSubmit(
        uint256 jobId,
        address,
        bytes32,
        bytes memory optParams
    ) internal override {
        (bytes32 cid, bytes[] memory wrappedKeys,) = abi.decode(optParams, (bytes32, bytes[], bytes));
        emit EncryptedSubmission(jobId, cid, envelopeCommitments[jobId], wrappedKeys);
    }

    /// @dev Clear envelope commitment on completion to free storage.
    function _postComplete(
        uint256 jobId,
        address,
        bytes32,
        bytes memory
    ) internal override {
        delete envelopeCommitments[jobId];
    }

    /// @dev Clear envelope commitment on rejection to free storage.
    function _postReject(
        uint256 jobId,
        address,
        bytes32,
        bytes memory
    ) internal override {
        delete envelopeCommitments[jobId];
    }

    // --- View functions ---

    function getPrivacyConfig(uint256 jobId) external view returns (
        address zkVerifier, uint8 minWrappedKeys, uint8 numPublicInputs, bool configured
    ) {
        PrivacyConfig memory config = privacyConfigs[jobId];
        return (config.zkVerifier, config.minWrappedKeys, config.numPublicInputs, config.configured);
    }

    function getEnvelopeCommitment(uint256 jobId) external view returns (bytes32) {
        return envelopeCommitments[jobId];
    }
}
