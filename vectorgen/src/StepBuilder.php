<?php
declare(strict_types=1);
namespace FediE2EE\PKD\VectorGen;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use Random\RandomException;
use SodiumException;

use function hash;
use function hash_hmac;
use function json_encode;
use function sodium_crypto_sign_detached;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * Builds test steps with all message representations.
 */
class StepBuilder
{
    private const string PKD_CONTEXT =
        'https://github.com/fedi-e2ee/public-key-directory/v1';
    private const string HPKE_KEY_ID_MSG =
        'fedi-e2ee/public-key-directory:v1:key-id';

    private int $stepCounter = 0;

    public function __construct(private readonly TestCase $testCase)
    {}

    /**
     * Build an AddKey step.
     *
     * @throws RandomException
     * @throws SodiumException
     */
    public function addKey(
        string $actor,
        bool $selfSigned = false,
        bool $expectFail = false,
        string $expectedError = ''
    ): TestStep {
        $identity = $this->testCase->getIdentity($actor);
        $publicKey = 'ed25519:' . $identity['ed25519']['public-key'];
        $signingKey = $identity['ed25519']['secret-key'];

        $message = $this->buildMessage('AddKey', [
            'actor' => $actor,
            'public-key' => $publicKey,
            'time' => (string) $this->getTimestamp()
        ], ['actor', 'public-key']);

        return $this->buildStep(
            $message,
            $signingKey,
            $expectFail,
            $expectedError,
            $selfSigned ? "AddKey (self-signed) for {$actor}" : "AddKey for {$actor}",
            function () use ($actor, $publicKey) {
                $keyId = Base64UrlSafe::encodeUnpadded(random_bytes(32));
                $this->testCase->addActorKey($actor, $keyId, $publicKey);
            }
        );
    }

    /**
     * Build a Fireproof step.
     *
     * @throws SodiumException
     */
    public function fireproof(
        string $actor,
        bool $expectFail = false,
        string $expectedError = ''
    ): TestStep {
        $identity = $this->testCase->getIdentity($actor);
        $signingKey = $identity['ed25519']['secret-key'];

        $message = $this->buildMessage('Fireproof', [
            'actor' => $actor,
            'time' => (string) $this->getTimestamp()
        ], ['actor']);

        return $this->buildStep(
            $message,
            $signingKey,
            $expectFail,
            $expectedError,
            "Fireproof for {$actor}",
            function () use ($actor) {
                $this->testCase->setFireproof($actor, true);
            }
        );
    }

    /**
     * Build an UndoFireproof step.
     *
     * @throws SodiumException
     */
    public function undoFireproof(
        string $actor,
        bool $expectFail = false,
        string $expectedError = ''
    ): TestStep {
        $identity = $this->testCase->getIdentity($actor);
        $signingKey = $identity['ed25519']['secret-key'];

        $message = $this->buildMessage('UndoFireproof', [
            'actor' => $actor,
            'time' => (string) $this->getTimestamp()
        ], ['actor']);

        return $this->buildStep(
            $message,
            $signingKey,
            $expectFail,
            $expectedError,
            "UndoFireproof for {$actor}",
            function () use ($actor) {
                $this->testCase->setFireproof($actor, false);
            }
        );
    }

    /**
     * Build a BurnDown step.
     *
     * @throws SodiumException
     */
    public function burnDown(
        string $operator,
        string $target,
        string $otp = '00000000',
        bool $expectFail = false,
        string $expectedError = ''
    ): TestStep {
        $identity = $this->testCase->getIdentity($operator);
        $signingKey = $identity['ed25519']['secret-key'];

        // BurnDown is NOT encrypted with HPKE
        $message = $this->buildMessage('BurnDown', [
            'actor' => $target,
            'operator' => $operator,
            'otp' => $otp,
            'time' => (string) $this->getTimestamp()
        ], ['actor', 'operator']);

        return $this->buildStep(
            $message,
            $signingKey,
            $expectFail,
            $expectedError,
            "BurnDown {$target} by {$operator}",
            function () use ($target) {
                // Clear all keys and aux-data for target
                $this->testCase->updateActorState($target, [
                    'public-keys' => [],
                    'aux-data' => [],
                    'fireproof' => false
                ]);
            },
            skipHpke: true
        );
    }

    /**
     * Build an AddAuxData step.
     *
     * @throws SodiumException
     */
    public function addAuxData(
        string $actor,
        string $auxType,
        string $auxData,
        bool $expectFail = false,
        string $expectedError = ''
    ): TestStep {
        $identity = $this->testCase->getIdentity($actor);
        $signingKey = $identity['ed25519']['secret-key'];

        $message = $this->buildMessage('AddAuxData', [
            'actor' => $actor,
            'aux-type' => $auxType,
            'aux-data' => $auxData,
            'time' => (string) $this->getTimestamp()
        ], ['actor', 'aux-data']);

        return $this->buildStep(
            $message,
            $signingKey,
            $expectFail,
            $expectedError,
            "AddAuxData ({$auxType}) for {$actor}",
            function () use ($actor, $auxType, $auxData) {
                // Track aux data in actor state
            }
        );
    }

    /**
     * Build a RevokeAuxData step.
     *
     * @throws SodiumException
     */
    public function revokeAuxData(
        string $actor,
        string $auxType,
        string $auxData,
        bool $expectFail = false,
        string $expectedError = ''
    ): TestStep {
        $identity = $this->testCase->getIdentity($actor);
        $signingKey = $identity['ed25519']['secret-key'];

        $message = $this->buildMessage('RevokeAuxData', [
            'actor' => $actor,
            'aux-type' => $auxType,
            'aux-data' => $auxData,
            'time' => (string) $this->getTimestamp()
        ], ['actor', 'aux-data']);

        return $this->buildStep(
            $message,
            $signingKey,
            $expectFail,
            $expectedError,
            "RevokeAuxData ({$auxType}) for {$actor}",
            function () {
                // Track revocation in actor state
            }
        );
    }

    /**
     * Build a RevokeKey step.
     *
     * @throws SodiumException
     */
    public function revokeKey(
        string $actor,
        string $publicKeyToRevoke,
        bool $expectFail = false,
        string $expectedError = ''
    ): TestStep {
        $identity = $this->testCase->getIdentity($actor);
        $signingKey = $identity['ed25519']['secret-key'];

        $message = $this->buildMessage('RevokeKey', [
            'actor' => $actor,
            'public-key' => $publicKeyToRevoke,
            'time' => (string) $this->getTimestamp()
        ], ['actor', 'public-key']);

        return $this->buildStep(
            $message,
            $signingKey,
            $expectFail,
            $expectedError,
            "RevokeKey for {$actor}",
            function () use ($actor, $publicKeyToRevoke) {
                // Find and revoke the key
            }
        );
    }

    /**
     * Build the message structure with encrypted fields.
     *
     * @param array<string, string> $fields
     * @param string[] $encryptedFields
     * @return array<string, mixed>
     */
    private function buildMessage(
        string $action,
        array $fields,
        array $encryptedFields
    ): array {
        $message = [];
        $symmetricKeys = [];

        foreach ($fields as $key => $value) {
            if (in_array($key, $encryptedFields, true)) {
                $symKey = $this->testCase->deriveSymmetricKey(
                    $key,
                    $this->stepCounter
                );
                $message[$key] = $this->encryptAttribute($value, $symKey);
                $symmetricKeys[$key] = $symKey;
            } else {
                $message[$key] = $value;
            }
        }

        return [
            '!pkd-context' => self::PKD_CONTEXT,
            'action' => $action,
            'message' => $message,
            'recent-merkle-root' => $this->testCase->getRecentMerkleRoot(),
            'symmetric-keys' => $symmetricKeys
        ];
    }

    /**
     * Simplified attribute encryption for test vectors.
     */
    private function encryptAttribute(string $plaintext, string $key): string
    {
        // Simplified encryption for test vectors
        // Real implementations use the full algorithm from spec
        return Base64UrlSafe::encodeUnpadded(
            $plaintext . '::encrypted-with::' . $key
        );
    }

    /**
     * Sign a protocol message.
     *
     * @param array<string, mixed> $message
     * @throws SodiumException
     */
    private function signMessage(array $message, string $secretKey): string
    {
        $pae = DeterministicKeyDerivation::pae([
            '!pkd-context',
            $message['!pkd-context'],
            'action',
            $message['action'],
            'message',
            json_encode(
                $message['message'],
                JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
            ),
            'recent-merkle-root',
            $message['recent-merkle-root']
        ]);

        $signature = sodium_crypto_sign_detached(
            $pae,
            Base64UrlSafe::decode($secretKey)
        );

        return Base64UrlSafe::encodeUnpadded($signature);
    }

    /**
     * Create HPKE-wrapped message with padding for length hiding.
     *
     * @param array<string, mixed> $signedMessage
     */
    private function wrapWithHpke(array $signedMessage): string
    {
        // Add padding to reach 1 KiB boundary (padding is NOT signed)
        $paddedMessage = $this->addPadding($signedMessage);

        $plaintext = json_encode(
            $paddedMessage,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );

        // For test vectors, we use a deterministic "encryption"
        // Real HPKE is randomized, so we document this as placeholder
        $serverPubKey = $this->testCase->serverKeys['hpke-encaps-key'];
        $aad = $this->calculateKeyId($serverPubKey);

        // Deterministic placeholder for test vectors
        $ciphertext = Base64UrlSafe::encodeUnpadded(
            hash('sha256', $plaintext . $serverPubKey, true) . $plaintext
        );

        return 'hpke:' . $ciphertext;
    }

    /**
     * Add padding field to reach 1 KiB boundary.
     *
     * Padding is NOT covered by the signature - it's added after signing.
     * For test vectors, we use repeated 'A' characters (decodes to NUL bytes).
     *
     * @param array<string, mixed> $signedMessage
     * @return array<string, mixed>
     */
    private function addPadding(array $signedMessage): array
    {
        // Calculate current size without padding
        $currentJson = json_encode(
            $signedMessage,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );
        $currentSize = strlen($currentJson);

        // Calculate target size (next 1 KiB boundary)
        $targetSize = (int) ceil($currentSize / 1024) * 1024;

        // Account for the padding field overhead: ,"padding":"..."}
        // We need to calculate how many 'A' characters to add
        // The JSON will grow by: ,"padding":"" + padding_length + closing }
        // But we're replacing the closing }, so it's: ,"padding":"" + padding_length
        $overhead = strlen(',"padding":"') + strlen('"');

        $paddingNeeded = $targetSize - $currentSize - $overhead;
        if ($paddingNeeded < 0) {
            // If adding the field pushes us over, go to next boundary
            $targetSize += 1024;
            $paddingNeeded = $targetSize - $currentSize - $overhead;
        }

        // Use repeated 'A' characters (base64url for NUL bytes)
        $signedMessage['padding'] = str_repeat('A', max(0, $paddingNeeded));

        return $signedMessage;
    }

    /**
     * Calculate HPKE key ID (AAD).
     */
    private function calculateKeyId(string $encapsKey): string
    {
        return hash_hmac(
            'sha256',
            self::HPKE_KEY_ID_MSG,
            Base64UrlSafe::decode($encapsKey),
            true
        );
    }

    /**
     * Create Merkle leaf data (what gets committed to the tree).
     *
     * @param array<string, mixed> $signedMessage
     */
    private function createMerkleLeaf(array $signedMessage): string
    {
        // Per spec: leaf = hash(message) || server_sig || hash(server_pk)
        $messageJson = json_encode(
            $signedMessage,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );

        $messageHash = hash('sha256', $messageJson, true);
        $serverSecretKey = Base64UrlSafe::decode(
            $this->testCase->serverKeys['sign-secret-key']
        );
        $serverSignature = sodium_crypto_sign_detached(
            $messageHash,
            $serverSecretKey
        );
        $serverPkHash = hash(
            'sha256',
            Base64UrlSafe::decode(
                $this->testCase->serverKeys['sign-public-key']
            ),
            true
        );

        return Base64UrlSafe::encodeUnpadded(
            $messageHash . $serverSignature . $serverPkHash
        );
    }

    /**
     * Build a complete test step.
     *
     * @param array<string, mixed> $message
     * @throws SodiumException
     */
    private function buildStep(
        array $message,
        string $signingKey,
        bool $expectFail,
        string $expectedError,
        string $description,
        callable $onSuccess,
        bool $skipHpke = false
    ): TestStep {
        $this->stepCounter++;

        $merkleRootBefore = $this->testCase->getCurrentMerkleRoot();

        // Sign the message
        $signedMessage = $message;
        $signedMessage['signature'] = $this->signMessage($message, $signingKey);

        // Create JSON representations
        $protocolMessageJson = json_encode(
            $message,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );
        $signedMessageJson = json_encode(
            $signedMessage,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );

        // HPKE wrap (unless it's BurnDown)
        $hpkeWrapped = $skipHpke ? '' : $this->wrapWithHpke($signedMessage);

        // Create merkle leaf
        $merkleLeaf = $this->createMerkleLeaf($signedMessage);

        // If success, apply state changes and update merkle tree
        if (!$expectFail) {
            $onSuccess();
            // Add leaf to merkle tree BEFORE capturing merkleRootAfter
            $this->testCase->addLeafToMerkleTree($merkleLeaf);
        }

        $merkleRootAfter = $expectFail
            ? $merkleRootBefore
            : $this->testCase->getCurrentMerkleRoot();

        $step = new TestStep(
            merkleRootBefore: $merkleRootBefore,
            merkleRootAfter: $merkleRootAfter,
            expectFail: $expectFail,
            protocolMessage: $protocolMessageJson,
            signedMessage: $signedMessageJson,
            hpkeWrappedMessage: $hpkeWrapped,
            merkleLeaf: $merkleLeaf,
            expectedError: $expectedError,
            description: $description
        );

        $this->testCase->addStep($step);

        return $step;
    }

    /**
     * Get deterministic timestamp for test vectors.
     */
    private function getTimestamp(): int
    {
        // Use a fixed base timestamp + step counter for determinism
        return 1776655443 + $this->stepCounter;
    }
}
