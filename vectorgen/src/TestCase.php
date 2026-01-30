<?php
declare(strict_types=1);
namespace FediE2EE\PKD\VectorGen;

use ParagonIE\ConstantTime\Base64UrlSafe;
use SodiumException;

/**
 * A complete test case with server keys, steps, and final state.
 */
class TestCase
{
    private MerkleTreeState $merkleTree;
    /** @var array<string, array{ed25519: array, x25519: array}> */
    private array $identities = [];
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
     * @throws SodiumException
     * @return array{ed25519: array, x25519: array}
     */
    public function getIdentity(string $actor): array
    {
        if (!isset($this->identities[$actor])) {
            $testCaseId = $this->seed . ':identity:' . $actor;
            $this->identities[$actor] = [
                'ed25519' => DeterministicKeyDerivation::deriveEd25519Keypair(
                    $testCaseId
                ),
                'x25519' => DeterministicKeyDerivation::deriveX25519Keypair(
                    $testCaseId
                )
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
        // Note: Leaf was already added via addLeafToMerkleTree() in StepBuilder
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
            'identities' => $this->identities,
            'steps' => array_map(fn(TestStep $s) => $s->toArray(), $this->steps),
            'final-mapping' => [
                'actors' => $this->actorState,
                'merkle-tree' => [
                    'root' => $this->merkleTree->getCurrentRoot(),
                    'leaf-count' => $this->merkleTree->getLeafCount(),
                    'leaves' => $this->merkleTree->getLeaves()
                ]
            ]
        ];
    }
}
