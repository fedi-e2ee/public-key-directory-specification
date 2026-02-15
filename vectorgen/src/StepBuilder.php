<?php
declare(strict_types=1);
namespace FediE2EE\PKD\VectorGen;

use FediE2EE\PKD\Crypto\Protocol\HPKEAdapter;
use FediE2EE\PKD\Crypto\SymmetricKey;
use JsonException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use Random\RandomException;
use SodiumException;
use function hash,
    hash_hmac,
    json_encode,
    sodium_crypto_sign_detached,
    substr;
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
    private DeterministicVersion1 $attrEncryption;

    public function __construct(private readonly TestCase $testCase)
    {
        $this->attrEncryption = new DeterministicVersion1();
    }

    /**
     * Build an AddKey step.
     *
     * When selfSigned is true, the new key signs for itself (only valid for first key).
     * When selfSigned is false, an existing key signs for a new/different key.
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

        if ($selfSigned) {
            // Self-signed: the new key is the same as the signing key
            $publicKey = 'ed25519:' . $identity['ed25519']['public-key'];
            $signingKey = $identity['ed25519']['secret-key'];
        } else {
            // Not self-signed: existing key signs for a new/different key
            // Sign with the primary identity key
            $signingKey = $identity['ed25519']['secret-key'];
            // Generate a new additional key for this actor
            $keyCount = $this->testCase->getActorKeyCount($actor);
            $additionalKey = $this->testCase->getAdditionalKey($actor, $keyCount);
            $publicKey = 'ed25519:' . $additionalKey['ed25519']['public-key'];
        }

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

        // BurnDown is NOT HPKE-wrapped but fields are attribute-encrypted.
        // otp is a top-level field, NOT inside the message map.
        $message = $this->buildMessage('BurnDown', [
            'actor' => $target,
            'operator' => $operator,
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
            skipHpke: true,
            extraTopLevel: ['otp' => $otp]
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
     * Uses Version1 attribute encryption from pkd-crypto.
     *
     * @param array<string, string> $fields
     * @param string[] $encryptedFields
     * @return array<string, mixed>
     *
     * @throws RandomException
     * @throws SodiumException
     */
    private function buildMessage(
        string $action,
        array $fields,
        array $encryptedFields
    ): array {
        $message = [];
        $symmetricKeys = [];
        $merkleRoot = $this->testCase->getRecentMerkleRoot();

        foreach ($fields as $key => $value) {
            if (in_array($key, $encryptedFields, true)) {
                $rawKey = DeterministicKeyDerivation::deriveSymmetricKey(
                    $this->testCase->seed
                        . ':step:' . $this->stepCounter
                        . ':' . $key,
                    $key
                );
                $symKey = new SymmetricKey($rawKey);
                $r = substr(
                    DeterministicKeyDerivation::deriveSeed(
                        $this->testCase->seed
                            . ':attr-enc-random:'
                            . $this->stepCounter
                            . ':' . $key
                    ),
                    0,
                    32
                );
                $this->attrEncryption->setRandomBytes($r);
                $ciphertext = $this->attrEncryption->encryptAttribute(
                    $key, $value, $symKey, $merkleRoot
                );
                $message[$key] = Base64UrlSafe::encodeUnpadded(
                    $ciphertext
                );
                $symmetricKeys[$key] = Base64UrlSafe::encodeUnpadded(
                    $rawKey
                );
            } else {
                $message[$key] = $value;
            }
        }
        ksort($message);
        ksort($symmetricKeys);

        $outer = [
            '!pkd-context' => self::PKD_CONTEXT,
            'action' => $action,
            'message' => $message,
            'recent-merkle-root' => $merkleRoot,
            'symmetric-keys' => $symmetricKeys
        ];
        ksort($outer);
        return $outer;
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
     * @throws JsonException
     * @throws HPKEException
     */
    private function wrapWithHpke(array $signedMessage): string
    {
        $paddedMessage = $this->addPadding($signedMessage);

        $plaintext = json_encode(
            $paddedMessage,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );

        $hpke = Factory::init(
            'DHKEM(X25519, HKDF-SHA256),'
            . ' HKDF-SHA256, ChaCha20Poly1305'
        );
        $encapsKey = new EncapsKey(
            Curve::X25519,
            Base64UrlSafe::decodeNoPadding(
                $this->testCase->serverKeys['hpke-encaps-key']
            )
        );

        return (new HPKEAdapter($hpke))->seal(
            encapsKey: $encapsKey,
            plaintext: $plaintext,
        );
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
    /**
     * @param array<string, mixed> $extraTopLevel Fields added to
     *   the transmitted JSON but excluded from the Merkle leaf
     *   (e.g. BurnDown otp).
     */
    private function buildStep(
        array $message,
        string $signingKey,
        bool $expectFail,
        string $expectedError,
        string $description,
        callable $onSuccess,
        bool $skipHpke = false,
        array $extraTopLevel = []
    ): TestStep {
        $this->stepCounter++;

        $merkleRootBefore = $this->testCase->getCurrentMerkleRoot();

        // Sign the message (extra top-level fields are NOT signed)
        $signedMessage = $message;
        $signedMessage['signature'] = $this->signMessage($message, $signingKey);
        ksort($signedMessage);

        // HPKE wrap (unless it's BurnDown)
        $hpkeWrapped = $skipHpke ? '' : $this->wrapWithHpke($signedMessage);

        // Create merkle leaf (before adding extra top-level fields)
        $merkleLeaf = $this->createMerkleLeaf($signedMessage);

        // Add extra top-level fields to the transmitted JSON
        // representations (e.g. otp), but NOT to the Merkle leaf.
        $protocolMessage = $message + $extraTopLevel;
        ksort($protocolMessage);
        $protocolMessageJson = json_encode(
            $protocolMessage,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );
        $transmitSigned = $signedMessage + $extraTopLevel;
        ksort($transmitSigned);
        $signedMessageJson = json_encode(
            $transmitSigned,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );

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
