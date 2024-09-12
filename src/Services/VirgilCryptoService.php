<?php
/**
 * Copyright (C) 2015-2024 Virgil Security Inc.
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Virgil\Crypto\Services;

use Exception;
use Virgil\Crypto\Core\Enum\HashAlgorithms;
use Virgil\Crypto\Core\Enum\KeyPairType;
use Virgil\Crypto\Core\Enum\SigningMode;
use Virgil\Crypto\Core\Enum\VerifyingMode;
use Virgil\Crypto\Core\Enum\VirgilCryptoError;
use Virgil\Crypto\Core\IO\StreamInterface;
use Virgil\Crypto\Core\SigningOptions;
use Virgil\Crypto\Core\VerifyingOptions;
use Virgil\Crypto\Core\VirgilKeys\VirgilKeyPair;
use Virgil\Crypto\Core\VirgilKeys\VirgilPrivateKey;
use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKey;
use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKeyCollection;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\CryptoWrapper\Foundation\KeyMaterialRng;
use Virgil\CryptoWrapper\Foundation\Random;
use Virgil\CryptoWrapper\Foundation\Aes256Gcm;
use Virgil\CryptoWrapper\Foundation\AlgId;
use Virgil\CryptoWrapper\Foundation\CtrDrbg;
use Virgil\CryptoWrapper\Foundation\KeyProvider;
use Virgil\CryptoWrapper\Foundation\PrivateKey;
use Virgil\CryptoWrapper\Foundation\PublicKey;
use Virgil\CryptoWrapper\Foundation\RecipientCipher;
use Virgil\CryptoWrapper\Foundation\Sha224;
use Virgil\CryptoWrapper\Foundation\Sha256;
use Virgil\CryptoWrapper\Foundation\Sha384;
use Virgil\CryptoWrapper\Foundation\Sha512;
use Virgil\CryptoWrapper\Foundation\Signer;
use Virgil\CryptoWrapper\Foundation\Verifier;

/**
 * Class VirgilCryptoService
 *
 * @package Virgil\Crypto\Services
 */
class VirgilCryptoService
{
    private const string CUSTOM_PARAM_KEY_SIGNATURE = "VIRGIL-DATA-SIGNATURE";
    private const string CUSTOM_PARAM_KEY_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID";

    /**
     * VirgilCryptoService constructor.
     *
     * @param KeyPairType $defaultKeyType
     * @param bool $useSHA256Fingerprints
     * @param Random $rng
     */
    public function __construct(
        private readonly KeyPairType $defaultKeyType,
        private readonly bool $useSHA256Fingerprints,
        private readonly Random $rng
    ) {
    }

    /**
     * @return CtrDrbg
     */
    private function getRandom(): Random
    {
        return $this->rng;
    }

    /**
     * @param PublicKey $publicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    private function computePublicKeyIdentifier(PublicKey $publicKey): string
    {
        try {
            $publicKeyData = $this->exportInternalPublicKey($publicKey);

            if ($this->useSHA256Fingerprints) {
                $res = $this->computeHash($publicKeyData, HashAlgorithms::SHA256());
            } else {
                $res = $this->computeHash($publicKeyData, HashAlgorithms::SHA512());
                $res = substr($res, 0, 8);
            }

            return $res;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param string $seed
     *
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    public function generateKeyPairUsingSeed(string $seed): VirgilKeyPair
    {
        $this->validateSeed($seed);

        try {
            $seedRng = new KeyMaterialRng();
            $seedRng->resetKeyMaterial($seed);

            return $this->generateKeyPair($this->defaultKeyType, $seedRng);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Validate the seed length.
     *
     * @param string $seed
     * @throws VirgilCryptoException
     */
    private function validateSeed(string $seed): void
    {
        $seedLength = strlen($seed);

        if ($seedLength < KeyMaterialRng::KEY_MATERIAL_LEN_MIN ||
            $seedLength > KeyMaterialRng::KEY_MATERIAL_LEN_MAX) {
            throw new VirgilCryptoException(VirgilCryptoError::INVALID_SEED_SIZE());
        }
    }


    /**
     * @param KeyPairType|null $type
     * @param Random|null $rng
     *
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    public function generateKeyPair(KeyPairType $type = null, Random $rng = null): VirgilKeyPair
    {
        try {
            $keyProvider = new KeyProvider();

            if (!$type) {
                $type = $this->defaultKeyType;
            }

            $bitLen = $type->getRsaBitLen($type);

            if ($bitLen) {
                $keyProvider->setRsaParams($bitLen);
            }

            if (!$rng) {
                $rng = $this->getRandom();
            }

            $keyProvider->useRandom($rng);
            $keyProvider->setupDefaults();

            $algId = $type->getAlgId($type);

            $privateKey = $keyProvider->generatePrivateKey($algId);
            $publicKey = $privateKey->extractPublicKey();
            $keyId = $this->computePublicKeyIdentifier($publicKey);

            $virgilPrivateKey = new VirgilPrivateKey($keyId, $privateKey, $type);
            $virgilPublicKey = new VirgilPublicKey($keyId, $publicKey, $type);

            return new VirgilKeyPair($virgilPrivateKey, $virgilPublicKey);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Generates digital signature of data using private key
     * - Note: Returned value contains only digital signature, not data itself.
     * - Note: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
     *   It's secure to pass raw data here.
     * - Note: Verification algorithm depends on PrivateKey type. Default: EdDSA for ed25519 key
     *
     * @param string $data
     * @param VirgilPrivateKey $virgilPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateSignature(string $data, VirgilPrivateKey $virgilPrivateKey): string
    {
        try {
            $signer = new Signer();
            $signer->useRandom($this->getRandom());
            $signer->useHash(new Sha512());

            $signer->reset();
            $signer->appendData($data);

            return $signer->sign($virgilPrivateKey->getPrivateKey());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param mixed $inputOutput
     * @param SigningOptions|null $signingOptions
     *
     * @throws VirgilCryptoException
     */
    private function startEncryption(
        RecipientCipher $cipher,
        mixed $inputOutput,
        SigningOptions $signingOptions = null
    ): void {
        try {
            if ($signingOptions) {
                $this->handleSigningOptions($cipher, $inputOutput, $signingOptions);
            } else {
                $cipher->startEncryption();
            }
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Handle signing options for encryption.
     *
     * @param RecipientCipher $cipher
     * @param mixed $inputOutput
     * @param SigningOptions $signingOptions
     * @throws VirgilCryptoException
     */
    private function handleSigningOptions(
        RecipientCipher $cipher,
        mixed $inputOutput,
        SigningOptions $signingOptions
    ): void {
        $signingMode = $signingOptions->getSigningMode();

        switch ($signingMode) {
            case $signingMode::SIGN_AND_ENCRYPT():
                $this->handleSignAndEncrypt($cipher, $inputOutput, $signingOptions);
                break;

            case $signingMode::SIGN_THEN_ENCRYPT():
                $this->handleSignThenEncrypt($cipher, $inputOutput, $signingOptions);
                break;
        }
    }

    /**
     * Handle sign and encrypt mode.
     *
     * @param RecipientCipher $cipher
     * @param mixed $inputOutput
     * @param SigningOptions $signingOptions
     * @throws VirgilCryptoException
     * @throws Exception
     */
    private function handleSignAndEncrypt(
        RecipientCipher $cipher,
        mixed $inputOutput,
        SigningOptions $signingOptions
    ): void {
        if (!is_string($inputOutput)) {
            throw new VirgilCryptoException("signAndEncrypt is supported only for strings");
        }

        $signature = $this->generateSignature($inputOutput, $signingOptions->getVirgilPrivateKey());
        $cipher->customParams()->addData(self::CUSTOM_PARAM_KEY_SIGNATURE, $signature);
        $cipher->customParams()->addData(
            self::CUSTOM_PARAM_KEY_SIGNER_ID,
            $signingOptions->getVirgilPrivateKey()->getIdentifier()
        );

        $cipher->startEncryption();
    }

    /**
     * Handle sign then encrypt mode.
     *
     * @param RecipientCipher $cipher
     * @param mixed $inputOutput
     * @param SigningOptions $signingOptions
     * @throws VirgilCryptoException
     * @throws Exception
     */
    private function handleSignThenEncrypt(
        RecipientCipher $cipher,
        mixed $inputOutput,
        SigningOptions $signingOptions
    ): void {
        $cipher->useSignerHash(new Sha512());
        $cipher->addSigner(
            $signingOptions->getVirgilPrivateKey()->getIdentifier(),
            $signingOptions->getVirgilPrivateKey()->getPrivateKey()
        );

        $size = $this->getInputSize($inputOutput);

        if ($size === null) {
            throw new VirgilCryptoException("Unsupported inputOutput type");
        }

        $cipher->startSignedEncryption($size);
    }

    /**
     * Get the size of the input.
     *
     * @param mixed $inputOutput
     * @return int|null
     * @throws VirgilCryptoException
     */
    private function getInputSize(mixed $inputOutput): ?int
    {
        if (is_string($inputOutput)) {
            return strlen($inputOutput);
        } elseif ($inputOutput instanceof StreamInterface) {
            if (!$inputOutput->getStreamSize()) {
                throw new VirgilCryptoException("signThenEncrypt for streams with unknown size is not supported");
            }
            return $inputOutput->getStreamSize();
        }
        return null;
    }


    /**
     * @param RecipientCipher $cipher
     * @param mixed $inputOutput
     * @param SigningOptions|null $signingOptions
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    private function processEncryption(
        RecipientCipher $cipher,
        mixed $inputOutput,
        SigningOptions $signingOptions = null
    ): ?string {
        try {
            if (is_string($inputOutput)) {
                return $this->processStringEncryption($cipher, $inputOutput, $signingOptions);
            } elseif ($inputOutput instanceof StreamInterface) {
                return $this->processStreamEncryption($cipher, $inputOutput, $signingOptions);
            } else {
                throw new VirgilCryptoException("Unsupported inputOutput type");
            }
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Process encryption for string input.
     *
     * @param RecipientCipher $cipher
     * @param string $input
     * @param SigningOptions|null $signingOptions
     * @return string|null
     * @throws Exception
     */
    private function processStringEncryption(
        RecipientCipher $cipher,
        string $input,
        SigningOptions $signingOptions = null
    ): ?string {
        $result = $cipher->packMessageInfo();
        $result .= $cipher->processEncryption($input);
        $result .= $cipher->finishEncryption();

        if ($signingOptions && $signingOptions->getSigningMode() === SigningMode::SIGN_THEN_ENCRYPT()) {
            $result .= $cipher->packMessageInfoFooter();
        }

        return $result;
    }

    /**
     * Process encryption for stream input.
     *
     * @param RecipientCipher $cipher
     * @param StreamInterface $inputOutput
     * @param SigningOptions|null $signingOptions
     * @return string|null
     * @throws Exception
     */
    private function processStreamEncryption(
        RecipientCipher $cipher,
        StreamInterface $inputOutput,
        SigningOptions
        $signingOptions = null
    ): ?string {
        $inputOutput->getOutputStream()->write($cipher->packMessageInfo());

        $chunkClosure = function ($chunk) use ($cipher) {
            return $cipher->processEncryption($chunk);
        };
        StreamService::forEachChunk($inputOutput, $chunkClosure, true);

        $inputOutput->getOutputStream()->write($cipher->finishEncryption());

        if ($signingOptions && $signingOptions->getSigningMode() === SigningMode::SIGN_THEN_ENCRYPT()) {
            $inputOutput->getOutputStream()->write($cipher->packMessageInfoFooter());
        }

        return null; // we return null, since the result is not saved
    }


    /**
     * Encrypts the given input using the provided recipients and signing options.
     *
     * @param mixed $inputOutput
     * @param VirgilPublicKeyCollection $recipients
     * @param SigningOptions|null $signingOptions
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function encrypt(
        mixed $inputOutput,
        VirgilPublicKeyCollection $recipients,
        SigningOptions $signingOptions = null
    ): ?string {
        try {
            $cipher = $this->initializeCipher($recipients);
            $this->startEncryption($cipher, $inputOutput, $signingOptions);

            return $this->processEncryption($cipher, $inputOutput, $signingOptions);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Initializes the RecipientCipher with the given recipients.
     *
     * @param VirgilPublicKeyCollection $recipients
     * @return RecipientCipher
     */
    private function initializeCipher(VirgilPublicKeyCollection $recipients): RecipientCipher
    {
        $aesGcm = new Aes256Gcm();
        $cipher = new RecipientCipher();

        $cipher->useEncryptionCipher($aesGcm);
        $cipher->useRandom($this->getRandom());

        foreach ($recipients->getAsArray() as $recipient) {
            $cipher->addKeyRecipient($recipient->getIdentifier(), $recipient->getPublicKey());
        }

        return $cipher;
    }


    /**
     * @param RecipientCipher $cipher
     * @param $inputOutput
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    private function processDecryption(RecipientCipher $cipher, $inputOutput): ?string
    {
        try {
            $result = null;

            if (is_string($inputOutput)) {
                $result = $cipher->processDecryption($inputOutput);
                $result .= $cipher->finishDecryption();
            } elseif ($inputOutput instanceof StreamInterface) {
                $chunkClosure = function ($chunk) use ($cipher) {
                    return $cipher->processDecryption($chunk);
                };

                StreamService::forEachChunk($inputOutput, $chunkClosure, true);
                $inputOutput->getOutputStream()->write($cipher->finishDecryption());
            } else {
                throw new VirgilCryptoException("Unsupported inputOutput type");
            }

            return $result;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param $inputOutput
     * @param string|null $result
     * @param VirgilPublicKeyCollection $publicKeys
     *
     * @return void
     * @throws VirgilCryptoException
     */
    private function verifyPlainSignature(
        RecipientCipher $cipher,
        $inputOutput,
        VirgilPublicKeyCollection $publicKeys,
        string $result = null
    ): void {
        try {
            $signerPublicKey = null;

            if ($inputOutput instanceof StreamInterface) {
                throw new VirgilCryptoException("signAndEncrypt is not supported for streams");
            }

            if (1 == $publicKeys->getAmountOfKeys()) {
                $signerPublicKey = $publicKeys->getFirst();
            } else {
                $signerId = $cipher->customParams()->findData(self::CUSTOM_PARAM_KEY_SIGNER_ID);

                if (!$signerId) {
                    throw new VirgilCryptoException(VirgilCryptoError::SIGNER_NOT_FOUND());
                }

                foreach ($publicKeys->getAsArray() as $publicKey) {
                    if ($publicKey->getIdentifier() == $signerId) {
                        $signerPublicKey = $publicKey;
                        break;
                    }
                }

                if (!$signerPublicKey) {
                    throw new VirgilCryptoException(VirgilCryptoError::SIGNER_NOT_FOUND());
                }
            }

            $signature = $cipher->customParams()->findData(self::CUSTOM_PARAM_KEY_SIGNATURE);

            if (!$signature) {
                throw new VirgilCryptoException(VirgilCryptoError::SIGNATURE_NOT_FOUND());
            }

            $result = $this->verifySignature($signature, $result, $signerPublicKey);

            if (!$result) {
                throw new VirgilCryptoException(VirgilCryptoError::SIGNATURE_NOT_VERIFIED());
            }

            return;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param VirgilPublicKeyCollection $publicKeys
     *
     * @return void
     * @throws VirgilCryptoException
     */
    private function verifyEncryptedSignature(RecipientCipher $cipher, VirgilPublicKeyCollection $publicKeys): void
    {
        try {
            $signerPublicKey = null;

            if (!$cipher->isDataSigned()) {
                throw new VirgilCryptoException(VirgilCryptoError::DATA_IS_NOT_SIGNED());
            }

            $signerInfoList = $cipher->signerInfos();

            $res = ($signerInfoList->hasItem() && !$signerInfoList->hasNext());
            if (!$res) {
                throw new VirgilCryptoException(VirgilCryptoError::DATA_IS_NOT_SIGNED());
            }

            $signerInfo = $signerInfoList->item();

            foreach ($publicKeys->getAsArray() as $publicKey) {
                if ($publicKey->getIdentifier() == $signerInfo->signerId()) {
                    $signerPublicKey = $publicKey->getPublicKey();
                    break;
                }
            }

            if (!$signerPublicKey) {
                throw new VirgilCryptoException(VirgilCryptoError::SIGNER_NOT_FOUND());
            }

            $result = $cipher->verifySignerInfo($signerInfo, $signerPublicKey);

            if (!$result) {
                throw new VirgilCryptoException(VirgilCryptoError::SIGNATURE_NOT_VERIFIED());
            }

            return;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Finishes the decryption process by verifying the signature if required.
     *
     * @param RecipientCipher $cipher
     * @param mixed $inputOutput
     * @param string|null $result
     * @param VerifyingOptions|null $verifyingOptions
     *
     * @throws VirgilCryptoException
     */
    private function finishDecryption(
        RecipientCipher $cipher,
        mixed $inputOutput,
        string $result = null,
        VerifyingOptions $verifyingOptions = null
    ): void {
        try {
            if ($verifyingOptions) {
                $this->handleVerification($cipher, $inputOutput, $verifyingOptions, $result);
            }
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Handles the verification process based on the provided verifying options.
     *
     * @param RecipientCipher $cipher
     * @param mixed $inputOutput
     * @param string|null $result
     * @param VerifyingOptions $verifyingOptions
     * @throws VirgilCryptoException
     */
    private function handleVerification(
        RecipientCipher $cipher,
        mixed $inputOutput,
        VerifyingOptions $verifyingOptions,
        string $result = null
    ): void {
        $mode = $this->determineVerifyingMode($cipher, $verifyingOptions);

        switch ($mode) {
            case VerifyingMode::DECRYPT_AND_VERIFY():
                $this->verifyPlainSignature($cipher, $inputOutput, $verifyingOptions->getVirgilPublicKeys(), $result);
                break;

            case VerifyingMode::DECRYPT_THEN_VERIFY():
                $this->verifyEncryptedSignature($cipher, $verifyingOptions->getVirgilPublicKeys());
                break;
        }
    }

    /**
     * Determines the verifying mode based on the cipher and verifying options.
     *
     * @param RecipientCipher $cipher
     * @param VerifyingOptions $verifyingOptions
     * @return VerifyingMode
     */
    private function determineVerifyingMode(RecipientCipher $cipher, VerifyingOptions $verifyingOptions): VerifyingMode
    {
        $mode = $verifyingOptions->getVerifyingMode();

        if ($mode === VerifyingMode::ANY()) {
            return $cipher->isDataSigned() ? VerifyingMode::DECRYPT_THEN_VERIFY() : VerifyingMode::DECRYPT_AND_VERIFY();
        }

        return $mode;
    }


    /**
     * @param $inputOutput
     * @param VirgilPrivateKey $privateKey
     * @param VerifyingOptions|null $verifyingOptions
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function decrypt($inputOutput, VirgilPrivateKey $privateKey, VerifyingOptions
    $verifyingOptions = null): ?string
    {
        try {
            $messageInfo = "";

            $cipher = new RecipientCipher();

            $cipher->useRandom($this->getRandom());

            $cipher->startDecryptionWithKey($privateKey->getIdentifier(), $privateKey->getPrivateKey(), $messageInfo);
            $result = $this->processDecryption($cipher, $inputOutput);

            $this->finishDecryption($cipher, $inputOutput, $result, $verifyingOptions);

            return $result;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Verifies digital signature of data
     * - Note: Verification algorithm depends on PublicKey type. Default: EdDSA for ed25519 key
     *
     * @param string $signature
     * @param string $data
     * @param VirgilPublicKey $virgilPublicKey
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    public function verifySignature(string $signature, string $data, VirgilPublicKey $virgilPublicKey): bool
    {
        try {
            $verifier = new Verifier();
            $verifier->reset($signature);
            $verifier->appendData($data);

            return $verifier->verify($virgilPublicKey->getPublicKey());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Generates digital signature of data stream using private key
     * - Note: Returned value contains only digital signature, not data itself.
     * - Note: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
     *         It's secure to pass raw data here.
     *
     * @param StreamInterface $stream
     * @param VirgilPrivateKey $virgilPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateStreamSignature(StreamInterface $stream, VirgilPrivateKey $virgilPrivateKey): string
    {
        try {
            $signer = new Signer();

            $signer->useRandom($this->getRandom());
            $signer->useHash(new Sha512());

            $signer->reset();

            $chunkClosure = function ($chunk) use ($signer) {
                $signer->appendData($chunk);
            };
            StreamService::forEachChunk($stream, $chunkClosure, false);

            return $signer->sign($virgilPrivateKey->getPrivateKey());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Verifies the digital signature of a data stream.
     * Note: Verification algorithm depends on the PublicKey type. Default: EdDSA.
     *
     * @param string $signature
     * @param StreamInterface $inputStream
     * @param VirgilPublicKey $virgilPublicKey
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    public function verifyStreamSignature(
        string $signature,
        StreamInterface $inputStream,
        VirgilPublicKey $virgilPublicKey
    ): bool {
        try {
            return $this->performVerification($signature, $inputStream, $virgilPublicKey);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Performs the signature verification process.
     *
     * @param string $signature
     * @param StreamInterface $inputStream
     * @param VirgilPublicKey $virgilPublicKey
     *
     * @return bool
     * @throws Exception
     */
    private function performVerification(
        string $signature,
        StreamInterface $inputStream,
        VirgilPublicKey $virgilPublicKey
    ): bool {
        $verifier = new Verifier();
        $verifier->reset($signature);

        $this->appendChunksToVerifier($inputStream, $verifier);

        return $verifier->verify($virgilPublicKey->getPublicKey());
    }

    /**
     * Appends chunks of data from the input stream to the verifier.
     *
     * @param StreamInterface $inputStream
     * @param Verifier $verifier
     */
    private function appendChunksToVerifier(StreamInterface $inputStream, Verifier $verifier): void
    {
        $chunkClosure = function ($chunk) use ($verifier) {
            $verifier->appendData($chunk);
        };

        StreamService::forEachChunk($inputStream, $chunkClosure, false);
    }


    /**
     * @param int $size
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateRandomData(int $size): string
    {
        try {
            return $this->getRandom()->random($size);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Computes hash
     *
     * @param string $data
     * @param HashAlgorithms $algorithm
     *
     * @return string
     */
    public function computeHash(string $data, HashAlgorithms $algorithm): string
    {
        $hash = match ((string)$algorithm) {
            (string)$algorithm::SHA224() => new Sha224(),
            (string)$algorithm::SHA256() => new Sha256(),
            (string)$algorithm::SHA384() => new Sha384(),
            (string)$algorithm::SHA512() => new Sha512(),
            default => new Sha512(),
        };

        return $hash::hash($data);
    }

    /**
     * @param string $data
     *
     * @return PrivateKey
     * @throws VirgilCryptoException
     */
    private function importInternalPrivateKey(string $data): PrivateKey
    {
        try {
            $keyProvider = new KeyProvider();

            $keyProvider->useRandom($this->getRandom());
            $keyProvider->setupDefaults();

            return $keyProvider->importPrivateKey($data);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param string $data
     *
     * @return PublicKey
     * @throws VirgilCryptoException
     */
    private function importInternalPublicKey(string $data): PublicKey
    {
        try {
            $keyProvider = new KeyProvider();

            $keyProvider->useRandom($this->getRandom());
            $keyProvider->setupDefaults();

            return $keyProvider->importPublicKey($data);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param string $data
     *
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    public function importPrivateKey(string $data): VirgilKeyPair
    {
        try {
            $privateKey = $this->importInternalPrivateKey($data);

            if ($privateKey->algId() == AlgId::RSA()) {
                $keyType = KeyPairType::getRsaKeyType($privateKey->bitLen());
            } else {
                $algId = $privateKey->algId();

                $keyType = KeyPairType::getFromAlgId($algId);
            }

            $publicKey = $privateKey->extractPublicKey();

            $keyId = $this->computePublicKeyIdentifier($publicKey);

            $virgilPrivateKey = new VirgilPrivateKey($keyId, $privateKey, $keyType);
            $virgilPublicKey = new VirgilPublicKey($keyId, $publicKey, $keyType);

            return new VirgilKeyPair($virgilPrivateKey, $virgilPublicKey);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param PrivateKey $privateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    private function exportInternalPrivateKey(PrivateKey $privateKey): string
    {
        try {
            $keyProvider = new KeyProvider();

            $keyProvider->useRandom($this->getRandom());
            $keyProvider->setupDefaults();

            return $keyProvider->exportPrivateKey($privateKey);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Extracts public key from private key
     *
     * @param VirgilPrivateKey $virgilPrivateKey
     *
     * @return VirgilPublicKey
     * @throws VirgilCryptoException
     */
    public function extractPublicKey(VirgilPrivateKey $virgilPrivateKey): VirgilPublicKey
    {
        try {
            $publicKey = $virgilPrivateKey->getPrivateKey()->extractPublicKey();

            return new VirgilPublicKey($virgilPrivateKey->getIdentifier(), $publicKey, $virgilPrivateKey->getKeyType());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param PublicKey $publicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    private function exportInternalPublicKey(PublicKey $publicKey): string
    {
        try {
            $keyProvider = new KeyProvider();

            $keyProvider->useRandom($this->getRandom());
            $keyProvider->setupDefaults();

            return $keyProvider->exportPublicKey($publicKey);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Imports public key from DER or PEM format
     *
     * @param string $data
     *
     * @return VirgilPublicKey
     * @throws VirgilCryptoException
     */
    public function importPublicKey(string $data): VirgilPublicKey
    {
        try {
            $publicKey = $this->importInternalPublicKey($data);

            if ($publicKey->algId() == AlgId::RSA()) {
                $keyType = KeyPairType::getRsaKeyType($publicKey->bitLen());
            } else {
                $algId = $publicKey->algId();
                $keyType = KeyPairType::getFromAlgId($algId);
            }

            $keyId = $this->computePublicKeyIdentifier($publicKey);

            return new VirgilPublicKey($keyId, $publicKey, $keyType);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Exports public key
     *
     * @param VirgilPublicKey $publicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function exportPublicKey(VirgilPublicKey $publicKey): string
    {
        try {
            return $this->exportInternalPublicKey($publicKey->getPublicKey());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Export private key
     *
     *
     * @param VirgilPrivateKey $privateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function exportPrivateKey(VirgilPrivateKey $privateKey): string
    {
        try {
            return $this->exportInternalPrivateKey($privateKey->getPrivateKey());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Signs (with private key) and then encrypts data/stream (and signature) for passed PublicKeys.
     * The process includes the following steps:
     * 1. Generates signature depending on KeyType.
     * 2. Generates random AES-256 KEY1.
     * 3. Encrypts data with KEY1 using AES-256-GCM and generates signature.
     * 4. Encrypts signature with KEY1 using AES-256-GCM.
     * 5. Generates ephemeral key pair for each recipient.
     * 6. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key.
     * 7. Computes KDF to obtain AES-256 key from shared secret for each recipient.
     * 8. Encrypts KEY1 with this key using AES-256-CBC for each recipient.
     *
     * @param mixed $inputOutput
     * @param VirgilPrivateKey $privateKey
     * @param VirgilPublicKeyCollection $recipients
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function authEncrypt(
        mixed $inputOutput,
        VirgilPrivateKey $privateKey,
        VirgilPublicKeyCollection $recipients
    ): ?string {
        try {
            $signingOptions = $this->createSigningOptions($privateKey);
            return $this->encryptData($inputOutput, $recipients, $signingOptions);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Creates signing options based on the provided private key.
     *
     * @param VirgilPrivateKey $privateKey
     * @return SigningOptions
     */
    private function createSigningOptions(VirgilPrivateKey $privateKey): SigningOptions
    {
        return new SigningOptions($privateKey, SigningMode::SIGN_THEN_ENCRYPT());
    }

    /**
     * Encrypts the provided data/stream with the specified recipients and signing options.
     *
     * @param mixed $inputOutput
     * @param VirgilPublicKeyCollection $recipients
     * @param SigningOptions $signingOptions
     * @return null|string
     * @throws VirgilCryptoException
     */
    private function encryptData(
        mixed $inputOutput,
        VirgilPublicKeyCollection $recipients,
        SigningOptions $signingOptions
    ): ?string {
        return $this->encrypt($inputOutput, $recipients, $signingOptions);
    }


    /**
     * Decrypts (with private key) data and signature and Verifies signature using any of signers' PublicKeys
     * or
     * Decrypts (using passed PrivateKey) then verifies (using one of public keys) stream
     *
     * - Note: Decrypted stream should not be used until decryption
     *         of whole InputStream completed due to security reasons
     *
     * 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
     * 2. Computes KDF to obtain AES-256 KEY2 from shared secret
     * 3. Decrypts KEY1 using AES-256-CBC
     * 4. Decrypts data and signature using KEY1 and AES-256-GCM
     * 5. Finds corresponding PublicKey according to signer id inside data
     * 6. Verifies signature
     *
     * @param $inputOutput
     * @param VirgilPrivateKey $privateKey
     * @param VirgilPublicKeyCollection $recipients
     * @param bool $allowNotEncryptedSignature
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function authDecrypt(
        $inputOutput,
        VirgilPrivateKey $privateKey,
        VirgilPublicKeyCollection $recipients,
        bool $allowNotEncryptedSignature = false
    ): ?string {
        try {
            $verifyMode = $allowNotEncryptedSignature ? VerifyingMode::ANY() : VerifyingMode::DECRYPT_THEN_VERIFY();
            $verifyingOptions = new VerifyingOptions($recipients, $verifyMode);

            return $this->decrypt($inputOutput, $privateKey, $verifyingOptions);
        } catch (Exception $e) {
            if ($e instanceof VirgilCryptoException) {
                throw $e;
            }

            throw new VirgilCryptoException($e);
        }
    }
}
