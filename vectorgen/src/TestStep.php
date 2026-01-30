<?php
declare(strict_types=1);
namespace FediE2EE\PKD\VectorGen;

/**
 * A single test step with all message representations.
 */
readonly class TestStep
{
    /**
     * @param string $merkleRootBefore Merkle root before this step
     * @param string $merkleRootAfter Merkle root after (same as before if rejected)
     * @param bool $expectFail Whether this step should be rejected
     * @param string $protocolMessage Plaintext protocol message JSON
     * @param string $signedMessage Protocol message with encrypted fields and signature
     * @param string $hpkeWrappedMessage HPKE-encrypted signed message (base64url with hpke: prefix)
     * @param string $merkleLeaf Data committed to Merkle tree (includes server signature)
     * @param string $expectedError Error message if expectFail is true
     * @param string $description Human-readable description
     */
    public function __construct(
        public string $merkleRootBefore,
        public string $merkleRootAfter,
        public bool   $expectFail,
        public string $protocolMessage,
        public string $signedMessage,
        public string $hpkeWrappedMessage,
        public string $merkleLeaf,
        public string $expectedError = '',
        public string $description = ''
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $result = [
            'merkle-root-before' => $this->merkleRootBefore,
            'merkle-root-after' => $this->merkleRootAfter,
            'expect-fail' => $this->expectFail,
            'protocol-message' => $this->protocolMessage,
            'signed-message' => $this->signedMessage,
            'hpke-wrapped-message' => $this->hpkeWrappedMessage,
            'merkle-leaf' => $this->merkleLeaf,
        ];

        if ($this->description !== '') {
            $result['description'] = $this->description;
        }

        if ($this->expectFail && $this->expectedError !== '') {
            $result['expected-error'] = $this->expectedError;
        }

        return $result;
    }
}
