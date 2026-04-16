<?php
declare(strict_types=1);
namespace FediE2EE\PKD\VectorGen;

use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * A complete test case with server keys, steps, and final state.
 */
class TestCase
{
    private MerkleTreeState $merkleTree;
    /** @var array<string, array{mldsa44: array, xwing: array}> */
    private array $identities = [];
    /** @var array<string, array<int, array{mldsa44: array, xwing: array}>> */
    private array $additionalKeys = [];
    /** @var array<string, array{fireproof: bool, public-keys: array, aux-data: array}> */
    private array $actorState = [];
    /** @var TestStep[] */
    private array $steps = [];

    /**
     * @param array{hpke-decaps-key: string, hpke-encaps-key: string, sign-secret-key: string, sign-public-key: string} $serverKeys
     */
    public function __construct(
        public readonly string $name,
        public readonly array $serverKeys,
        public readonly string $seed
    ) {
        $this->merkleTree = new MerkleTreeState();
    }

    /**
     * Get or create identity for an actor.
     *
     * @return array{mldsa44: array, xwing: array}
     */
    public function getIdentity(string $actor): array
    {
        if (!isset($this->identities[$actor])) {
            $testCaseId = $this->seed . ':identity:' . $actor;
            $this->identities[$actor] = [
                'mldsa44' => DeterministicKeyDerivation::deriveMlDsa44Keypair($testCaseId),
                'xwing' => DeterministicKeyDerivation::deriveXWingKeypair($testCaseId),
            ];
            $this->actorState[$actor] = [
                'fireproof' => false,
                'public-keys' => [],
                'aux-data' => []
            ];
        }
        return $this->identities[$actor];
    }

    /**
     * @return array{mldsa44: array, xwing: array}
     */
    public function getAdditionalKey(string $actor, int $keyIndex = 1): array
    {
        if (!isset($this->additionalKeys[$actor][$keyIndex])) {
            $keyId = $this->seed . ':identity:' . $actor . ':key:' . $keyIndex;
            $this->additionalKeys[$actor][$keyIndex] = [
                'mldsa44' => DeterministicKeyDerivation::deriveMlDsa44Keypair($keyId),
                'xwing' => DeterministicKeyDerivation::deriveXWingKeypair($keyId),
            ];
        }
        return $this->additionalKeys[$actor][$keyIndex];
    }

    public function getActorKeyCount(string $actor): int
    {
        return isset($this->actorState[$actor]['public-keys'])
            ? count($this->actorState[$actor]['public-keys'])
            : 0;
    }

    /**
     * Derive a deterministic symmetric key for this test case.
     */
    public function deriveSymmetricKey(string $purpose, int $stepIndex): string
    {
        $keyId = $this->seed . ':step:' . $stepIndex . ':' . $purpose;
        return Base64UrlSafe::encodeUnpadded(
            DeterministicKeyDerivation::deriveSymmetricKey($keyId, $purpose)
        );
    }

    /**
     * Get current Merkle root.
     */
    public function getCurrentMerkleRoot(): string
    {
        return $this->merkleTree->getCurrentRoot();
    }

    /**
     * Get recent Merkle root for message signing.
     */
    public function getRecentMerkleRoot(): string
    {
        return $this->merkleTree->getRecentRoot();
    }

    /**
     * Add a leaf to the Merkle tree (called before capturing merkleRootAfter).
     */
    public function addLeafToMerkleTree(string $leaf): void
    {
        $this->merkleTree->addLeaf($leaf);
    }

    /**
     * Add a step to this test case.
     */
    public function addStep(TestStep $step): void
    {
        $this->steps[] = $step;
    }

    /**
     * Update actor state after a successful operation.
     *
     * @param array<string, mixed> $changes
     */
    public function updateActorState(string $actor, array $changes): void
    {
        if (!isset($this->actorState[$actor])) {
            $this->actorState[$actor] = [
                'fireproof' => false,
                'public-keys' => [],
                'aux-data' => []
            ];
        }
        $this->actorState[$actor] = array_merge(
            $this->actorState[$actor],
            $changes
        );
    }

    /**
     * Add a public key to actor state.
     */
    public function addActorKey(string $actor, string $keyId, string $publicKey): void
    {
        if (!isset($this->actorState[$actor])) {
            $this->actorState[$actor] = [
                'fireproof' => false,
                'public-keys' => [],
                'aux-data' => []
            ];
        }
        $this->actorState[$actor]['public-keys'][$keyId] = [
            'public-key' => $publicKey,
            'revoked' => false
        ];
    }

    /**
     * Set fireproof status.
     */
    public function setFireproof(string $actor, bool $fireproof): void
    {
        if (isset($this->actorState[$actor])) {
            $this->actorState[$actor]['fireproof'] = $fireproof;
        }
    }

    /**
     * @return array<string, array{mldsa44: array, xwing: array}|array<string, array>>
     */
    private function mergeAllIdentityKeys(): array
    {
        $result = [];
        foreach ($this->identities as $actor => $primaryKey) {
            $result[$actor] = $primaryKey;
            // Add any additional keys as indexed entries
            if (isset($this->additionalKeys[$actor])) {
                foreach ($this->additionalKeys[$actor] as $index => $additionalKey) {
                    $result[$actor . ':key:' . $index] = $additionalKey;
                }
            }
        }
        return $result;
    }

    /**
     * Convert to output array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'seed' => $this->seed,
            'server-keys' => $this->serverKeys,
            'identities' => $this->mergeAllIdentityKeys(),
            'steps' => array_map(
                fn(TestStep $s) => $s->toArray(),
                $this->steps
            ),
            'final-mapping' => [
                'actors' => $this->actorState,
                'merkle-tree' => [
                    'root' =>
                        $this->merkleTree->getCurrentRoot(),
                    'leaf-count' =>
                        $this->merkleTree->getLeafCount(),
                    'leaves' =>
                        $this->merkleTree->getLeaves(),
                ]
            ]
        ];
    }
}
