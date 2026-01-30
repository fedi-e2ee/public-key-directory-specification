<?php
declare(strict_types=1);

namespace FediE2EE\PKD\VectorGen;

use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * Tracks Merkle tree state for test vector generation.
 *
 * Implements RFC 9162 style Merkle tree with domain separation.
 */
class MerkleTreeState
{
    /** @var string[] Raw leaf data (before hashing) */
    private array $leaves = [];
    /** @var string[] Hashed leaves */
    private array $leafHashes = [];
    private string $currentRoot;

    private const LEAF_PREFIX = "\x00";
    private const NODE_PREFIX = "\x01";

    public function __construct()
    {
        $this->currentRoot = $this->calculateInitialRoot();
    }

    /**
     * Get the initial Merkle root for an empty tree.
     */
    private function calculateInitialRoot(): string
    {
        $zeroHash = str_repeat("\x00", 32);
        return 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded($zeroHash);
    }

    /**
     * Hash a leaf with domain separation (RFC 9162).
     */
    private function hashLeaf(string $data): string
    {
        return hash('sha256', self::LEAF_PREFIX . $data, true);
    }

    /**
     * Hash two nodes together with domain separation (RFC 9162).
     */
    private function hashNodes(string $left, string $right): string
    {
        return hash('sha256', self::NODE_PREFIX . $left . $right, true);
    }

    /**
     * Calculate Merkle root from leaf hashes.
     */
    private function calculateRoot(): string
    {
        if (count($this->leafHashes) === 0) {
            return $this->calculateInitialRoot();
        }

        $nodes = $this->leafHashes;

        while (count($nodes) > 1) {
            $nextLevel = [];
            for ($i = 0; $i < count($nodes); $i += 2) {
                if (isset($nodes[$i + 1])) {
                    $nextLevel[] = $this->hashNodes($nodes[$i], $nodes[$i + 1]);
                } else {
                    // Odd node - promote to next level
                    $nextLevel[] = $nodes[$i];
                }
            }
            $nodes = $nextLevel;
        }

        return 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded($nodes[0]);
    }

    /**
     * Add a leaf to the tree.
     *
     * @param string $leafData Raw leaf data (will be hashed)
     */
    public function addLeaf(string $leafData): void
    {
        $this->leaves[] = $leafData;
        $this->leafHashes[] = $this->hashLeaf($leafData);
        $this->currentRoot = $this->calculateRoot();
    }

    /**
     * Add a protocol message to the tree (legacy API).
     */
    public function addMessage(string $messageJson): void
    {
        $this->addLeaf($messageJson);
    }

    /**
     * Get current Merkle root.
     */
    public function getCurrentRoot(): string
    {
        return $this->currentRoot;
    }

    /**
     * Get the number of leaves in the tree.
     */
    public function getLeafCount(): int
    {
        return count($this->leaves);
    }

    /**
     * Get all leaves (base64url encoded).
     *
     * @return string[]
     */
    public function getLeaves(): array
    {
        return array_map(
            fn($leaf) => Base64UrlSafe::encodeUnpadded($leaf),
            $this->leaves
        );
    }

    /**
     * Get a recent Merkle root suitable for inclusion in messages.
     */
    public function getRecentRoot(): string
    {
        if (count($this->leaves) === 0) {
            return $this->calculateInitialRoot();
        }
        return $this->currentRoot;
    }

    /**
     * Calculate inclusion proof for a leaf.
     *
     * @return string[] Array of sibling hashes (base64url encoded)
     */
    public function getInclusionProof(int $leafIndex): array
    {
        if ($leafIndex >= count($this->leafHashes)) {
            return [];
        }

        $proof = [];
        $nodes = $this->leafHashes;
        $idx = $leafIndex;

        while (count($nodes) > 1) {
            $siblingIdx = ($idx % 2 === 0) ? $idx + 1 : $idx - 1;
            if ($siblingIdx < count($nodes)) {
                $proof[] = Base64UrlSafe::encodeUnpadded($nodes[$siblingIdx]);
            }

            $nextLevel = [];
            for ($i = 0; $i < count($nodes); $i += 2) {
                if (isset($nodes[$i + 1])) {
                    $nextLevel[] = $this->hashNodes($nodes[$i], $nodes[$i + 1]);
                } else {
                    $nextLevel[] = $nodes[$i];
                }
            }
            $nodes = $nextLevel;
            $idx = (int) floor($idx / 2);
        }

        return $proof;
    }
}
