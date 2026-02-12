<?php
declare(strict_types=1);
namespace FediE2EE\PKD\VectorGen;

use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\SymmetricKey;
use Override;
use Random\RandomException;
use SodiumException;

use function
    hash,
    hash_hkdf,
    hash_hmac,
    random_bytes,
    sodium_crypto_stream_xor,
    substr;

/**
 * Version1 with injectable randomness for deterministic
 * test vector generation.
 *
 * All crypto logic is identical to Version1. The only
 * difference is the source of the 32-byte random value
 * `r` used in attribute encryption.
 */
class DeterministicVersion1 extends Version1
{
    private ?string $pendingRandom = null;

    /**
     * Pre-set the random bytes for the next
     * encryptAttribute() call.
     *
     * If not set, falls back to random_bytes(32).
     */
    public function setRandomBytes(string $r): void
    {
        $this->pendingRandom = $r;
    }

    /**
     * @throws RandomException
     * @throws SodiumException
     */
    #[Override]
    public function encryptAttribute(
        string $attributeName,
        string $plaintext,
        SymmetricKey $ikm,
        string $merkleRoot
    ): string {
        $h = self::VERSION;
        if ($this->pendingRandom !== null) {
            $r = $this->pendingRandom;
            $this->pendingRandom = null;
        } else {
            $r = random_bytes(32);
        }

        $encInfo = self::KDF_ENCRYPT_KEY . $h . $r
            . self::len($attributeName) . $attributeName;
        $encKeyNonce = hash_hkdf(
            'sha512', $ikm->getBytes(), 56, $encInfo, ''
        );
        $Ek = substr($encKeyNonce, 0, 32);
        $n = substr($encKeyNonce, 32, 24);

        $authInfo = self::KDF_AUTH_KEY . $h . $r
            . self::len($attributeName) . $attributeName;
        $Ak = hash_hkdf(
            'sha512', $ikm->getBytes(), 32, $authInfo, ''
        );

        $saltInfo = self::KDF_COMMIT_SALT . $h . $r
            . self::len($merkleRoot) . $merkleRoot
            . self::len($attributeName) . $attributeName;
        $s = substr(hash('sha512', $saltInfo, true), 0, 16);

        $Q = $this->getPlaintextCommitment(
            $attributeName, $plaintext, $merkleRoot, $s
        );

        $c = sodium_crypto_stream_xor($plaintext, $n, $Ek);

        $t = substr(
            hash_hmac(
                'sha512',
                $h . $r
                    . self::len($attributeName) . $attributeName
                    . self::len($c) . $c
                    . self::len($Q) . $Q,
                $Ak,
                true
            ),
            0,
            32
        );

        return $h . $r . $Q . $t . $c;
    }
}
