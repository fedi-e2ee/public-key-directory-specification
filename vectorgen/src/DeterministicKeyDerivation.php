<?php
declare(strict_types=1);

namespace FediE2EE\PKD\VectorGen;

use FediE2EE\PKD\Crypto\Enums\SigningAlgorithm;
use FediE2EE\PKD\Crypto\SecretKey;
use ParagonIE\ConstantTime\{Base64UrlSafe, Binary};
use ParagonIE\PQCrypto\Compat;

use function hash_hmac;
use function hash_hkdf;

/**
 * Deterministic key derivation for test vectors.
 *
 * Uses HMAC-SHA512 with repository URL as key and test case ID
 * as message to derive keypairs deterministically.
 */
class DeterministicKeyDerivation
{
    private const REPO_URL = 'https://github.com/fedi-e2ee/' .
        'public-key-directory-specification';

    /**
     * Pre-Authentication Encoding function from PASETO spec.
     *
     * @param array<int, string> $pieces
     */
    public static function pae(array $pieces): string
    {
        $output = self::le64(count($pieces));
        foreach ($pieces as $piece) {
            $output .= self::le64(Binary::safeStrlen($piece));
            $output .= $piece;
        }
        return $output;
    }

    /**
     * Little-endian 64-bit encoding.
     */
    public static function le64(int $n): string
    {
        return pack('P', $n);
    }

    /**
     * Derive a seed from test case ID using HMAC-SHA512.
     */
    public static function deriveSeed(string $testCaseId): string
    {
        return hash_hmac(
            'sha512',
            $testCaseId,
            self::REPO_URL,
            true
        );
    }

    /**
     * Derive ML-DSA-44 keypair from test case ID.
     *
     * @return array{secret-key: string, public-key: string}
     */
    public static function deriveMlDsa44Keypair(
        string $testCaseId
    ): array {
        $ikm = self::deriveSeed($testCaseId);
        $seed = hash_hkdf(
            'sha512',
            $ikm,
            32,
            self::pae(['mldsa44', $testCaseId])
        );

        $sk = new SecretKey($seed, SigningAlgorithm::MLDSA44);
        $pk = $sk->getPublicKey();

        return [
            'secret-key' => Base64UrlSafe::encodeUnpadded(
                $sk->getBytes()
            ),
            'public-key' => Base64UrlSafe::encodeUnpadded(
                $pk->getBytes()
            ),
        ];
    }

    /**
     * Derive X-Wing keypair (for HPKE) from test case ID.
     *
     * @return array{secret-key: string, public-key: string}
     */
    public static function deriveXWingKeypair(
        string $testCaseId
    ): array {
        $ikm = self::deriveSeed($testCaseId);
        $seed = hash_hkdf(
            'sha512',
            $ikm,
            32,
            self::pae(['xwing', $testCaseId])
        );

        [$dk, $ek] = Compat::xwing_seed_keypair($seed);

        return [
            'secret-key' => Base64UrlSafe::encodeUnpadded(
                $dk->bytes()
            ),
            'public-key' => Base64UrlSafe::encodeUnpadded(
                $ek->bytes()
            ),
        ];
    }

    /**
     * Derive a 256-bit symmetric key from test case ID.
     */
    public static function deriveSymmetricKey(
        string $testCaseId,
        string $purpose
    ): string {
        $ikm = self::deriveSeed($testCaseId);
        return hash_hkdf(
            'sha512',
            $ikm,
            32,
            self::pae(['symmetric', $purpose, $testCaseId])
        );
    }
}
