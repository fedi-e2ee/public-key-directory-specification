#!/usr/bin/env php
<?php
declare(strict_types=1);

use FediE2EE\PKD\VectorGen\DeterministicKeyDerivation;
use FediE2EE\PKD\VectorGen\StepBuilder;
use FediE2EE\PKD\VectorGen\TestCase;

/**
 * Usage: php generate.php > output/test-vectors.json
 */

require_once __DIR__ . '/vendor/autoload.php';

/**
 * Generate deterministic server keys for a test case.
 *
 * @return array{hpke-decaps-key: string, hpke-encaps-key: string, sign-secret-key: string, sign-public-key: string}
 * @throws SodiumException
 */
function generateServerKeys(string $seed): array
{
    $ed25519 = DeterministicKeyDerivation::deriveEd25519Keypair(
        $seed . ':server:ed25519'
    );
    $x25519 = DeterministicKeyDerivation::deriveX25519Keypair(
        $seed . ':server:x25519'
    );

    return [
        'hpke-decaps-key' => $x25519['secret-key'],
        'hpke-encaps-key' => $x25519['public-key'],
        'sign-secret-key' => $ed25519['secret-key'],
        'sign-public-key' => $ed25519['public-key']
    ];
}

/**
 * Test Case 1: Basic enrollment and fireproof flow
 * @throws SodiumException
 */
function testBasicFlow(): TestCase
{
    $seed = 'test-01-basic-flow';
    $tc = new TestCase(
        'basic-enrollment-and-fireproof',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    // Alice enrolls (self-signed)
    $builder->addKey('https://example.com/users/alice', selfSigned: true);
    // Alice becomes fireproof
    $builder->fireproof('https://example.com/users/alice');
    // Bob enrolls (self-signed)
    $builder->addKey('https://example.com/users/bob', selfSigned: true);
    // Bob becomes fireproof
    $builder->fireproof('https://example.com/users/bob');

    return $tc;
}

/**
 * Test Case 2: BurnDown blocked by Fireproof
 * @throws SodiumException
 */
function testFireproofBlocksBurndown(): TestCase
{
    $seed = 'test-02-fireproof-blocks-burndown';
    $tc = new TestCase(
        'fireproof-prevents-burndown',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    // Alice enrolls and becomes fireproof
    $builder->addKey('https://example.com/users/alice', selfSigned: true);
    $builder->fireproof('https://example.com/users/alice');
    // Bob enrolls (to be the operator)
    $builder->addKey('https://example.com/users/bob', selfSigned: true);
    // Bob tries to BurnDown Alice - MUST FAIL
    $builder->burnDown(
        operator: 'https://example.com/users/bob',
        target: 'https://example.com/users/alice',
        expectFail: true,
        expectedError: 'Actor is Fireproof'
    );

    return $tc;
}

/**
 * Test Case 3: Cannot self-sign AddKey when keys exist
 * @throws SodiumException
 */
function testCannotSelfSignWithExistingKeys(): TestCase
{
    $seed = 'test-03-no-self-sign-existing';
    $tc = new TestCase(
        'cannot-self-sign-with-existing-keys',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    // Alice enrolls (self-signed) - succeeds
    $builder->addKey('https://example.com/users/alice', selfSigned: true);
    // Alice tries another self-signed AddKey - MUST FAIL
    $builder->addKey(
        'https://example.com/users/alice',
        selfSigned: true,
        expectFail: true,
        expectedError: 'Self-signed AddKey not allowed when keys exist'
    );

    return $tc;
}

/**
 * Test Case 4: Cannot double Fireproof
 * @throws SodiumException
 */
function testCannotDoubleFireproof(): TestCase
{
    $seed = 'test-04-no-double-fireproof';
    $tc = new TestCase(
        'cannot-fireproof-twice',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    // Alice enrolls
    $builder->addKey('https://example.com/users/alice', selfSigned: true);
    // Alice becomes fireproof
    $builder->fireproof('https://example.com/users/alice');
    // Alice tries to Fireproof again - MUST FAIL
    $builder->fireproof(
        'https://example.com/users/alice',
        expectFail: true,
        expectedError: 'Actor is already Fireproof'
    );
    return $tc;
}

/**
 * Test Case 5: Cannot UndoFireproof when not Fireproof
 * @throws SodiumException
 */
function testCannotUndoFireproofWhenNotFireproof(): TestCase
{
    $seed = 'test-05-no-undo-without-fireproof';
    $tc = new TestCase(
        'cannot-undo-fireproof-without-fireproof',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    // Alice enrolls (not fireproof)
    $builder->addKey('https://example.com/users/alice', selfSigned: true);
    // MUST FAIL
    $builder->undoFireproof(
        'https://example.com/users/alice',
        expectFail: true,
        expectedError: 'Actor is not Fireproof'
    );
    return $tc;
}

/**
 * Test Case 6: BurnDown cross-domain blocked
 * @throws SodiumException
 */
function testBurndownCrossDomainBlocked(): TestCase
{
    $seed = 'test-06-burndown-cross-domain';
    $tc = new TestCase(
        'burndown-blocked-cross-domain',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    $builder->addKey('https://example.com/users/alice', selfSigned: true);
    $builder->addKey('https://evil.com/users/mallory', selfSigned: true);
    $builder->burnDown(
        operator: 'https://evil.com/users/mallory',
        target: 'https://example.com/users/alice',
        expectFail: true,
        expectedError: 'Operator and target domains must match'
    );

    return $tc;
}

/**
 * Test Case 7: Complete protocol message flow
 * @throws SodiumException
 */
function testCompleteProtocolFlow(): TestCase
{
    $seed = 'test-07-complete-flow';
    $tc = new TestCase(
        'complete-protocol-message-flow',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    $actor = 'https://example.org/users/carol';
    $builder->addKey($actor, selfSigned: true);
    $builder->addAuxData(
        $actor,
        'age-v1',
        'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p'
    );
    $builder->fireproof($actor);
    $builder->undoFireproof($actor);
    $builder->revokeAuxData(
        $actor,
        'age-v1',
        'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p'
    );

    return $tc;
}

/**
 * Test Case 8: Operations on non-existent actor
 * @throws SodiumException
 */
function testOperationsOnNonExistentActor(): TestCase
{
    $seed = 'test-08-non-existent-actor';
    $tc = new TestCase(
        'operations-on-non-existent-actor',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    $actor = 'https://example.com/users/ghost';
    // MUST FAIL
    $builder->fireproof(
        $actor,
        expectFail: true,
        expectedError: 'Actor has no enrolled keys'
    );
    return $tc;
}

/**
 * Test Case 9: Successful BurnDown (non-fireproof actor)
 * @throws SodiumException
 */
function testSuccessfulBurndown(): TestCase
{
    $seed = 'test-09-successful-burndown';
    $tc = new TestCase(
        'successful-burndown-non-fireproof',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    $builder->addKey('https://example.com/users/alice', selfSigned: true);
    $builder->addKey('https://example.com/users/bob', selfSigned: true);
    $builder->burnDown(
        operator: 'https://example.com/users/alice',
        target: 'https://example.com/users/bob',
        otp: '12345678'
    );
    return $tc;
}

/**
 * Test Case 10: Key management lifecycle
 * @throws SodiumException
 */
function testKeyManagementLifecycle(): TestCase
{
    $seed = 'test-10-key-lifecycle';
    $tc = new TestCase(
        'key-management-lifecycle',
        generateServerKeys($seed),
        $seed
    );
    $builder = new StepBuilder($tc);
    $actor = 'https://example.com/users/dave';
    $builder->addKey($actor, selfSigned: true);
    $builder->addKey($actor);

    return $tc;
}

try {
    $testCases = [
            testBasicFlow(),
            testFireproofBlocksBurndown(),
            testCannotSelfSignWithExistingKeys(),
            testCannotDoubleFireproof(),
            testCannotUndoFireproofWhenNotFireproof(),
            testBurndownCrossDomainBlocked(),
            testCompleteProtocolFlow(),
            testOperationsOnNonExistentActor(),
            testSuccessfulBurndown(),
            testKeyManagementLifecycle(),
    ];

    $output = [
            'version' => '0.6.1',
            'specification' => 'https://github.com/fedi-e2ee/public-key-directory-specification',
            'generated' => date('c'),
            'description' => 'Complete test vectors for PKD specification. ' .
                    'Includes both acceptance tests and rejection tests.',
            'step-field-semantics' => [
                    'merkle-root-before' => 'Merkle root before processing this step',
                    'merkle-root-after' => 'Merkle root after acceptance; equals merkle-root-before if rejected',
                    'expect-fail' => 'If true, this step MUST be rejected by implementations',
                    'protocol-message' => 'Unsigned protocol message with symmetric keys for encrypted fields',
                    'signed-message' => 'Protocol message with Ed25519 signature appended',
                    'hpke-wrapped-message' => 'Signed message with padding, HPKE-encrypted (empty for BurnDown)',
                    'merkle-leaf' => 'Data committed to Merkle tree: hash || server_sig || server_pk_hash',
                    'expected-error' => 'Error description (only present when expect-fail is true)',
                    'description' => 'Human-readable description of the step'
            ],
            'test-cases' => array_map(fn(TestCase $tc) => $tc->toArray(), $testCases)
    ];

    echo json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (SodiumException $e) {
    echo $e->getMessage();
    exit(1);
}
