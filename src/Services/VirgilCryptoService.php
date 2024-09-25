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
    /**
     * @var KeyPairType
     */
    private KeyPairType $defaultKeyType;

    /**
     * @var bool
     */
    private bool $useSHA256Fingerprints;

    /**
     * @var int
     */
    private int $chunkSize;

    /**
     * @var Random
     */
    private Random $rng;

    private const string CUSTOM_PARAM_KEY_SIGNATURE = "VIRGIL-DATA-SIGNATURE";
    private const string CUSTOM_PARAM_KEY_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID";

    /**
     * VirgilCryptoService constructor.
     *
     * @param KeyPairType $defaultKeyType
     * @param bool $useSHA256Fingerprints
     * @param int $chunkSize
     * @param Random $rng
     */
    public function __construct(KeyPairType $defaultKeyType, bool $useSHA256Fingerprints, int $chunkSize, Random $rng)
    {
        $this->defaultKeyType = $defaultKeyType;
        $this->useSHA256Fingerprints = $useSHA256Fingerprints;
        $this->chunkSize = $chunkSize;
        $this->rng = $rng;
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
    ): void
    {
        try {
            if ($signingOptions) {
                $signingMode = $signingOptions->getSigningMode();

                $virgilPrivateKey = $signingOptions->getVirgilPrivateKey();
                switch ($signingMode) {
                    case $signingMode::SIGN_AND_ENCRYPT():

                        if (is_string($inputOutput)) {
                                $signature = $this->generateSignature($inputOutput, $virgilPrivateKey);
                                $cipher->customParams()->addData(self::CUSTOM_PARAM_KEY_SIGNATURE, $signature);
                                $cipher->customParams()->addData(self::CUSTOM_PARAM_KEY_SIGNER_ID,
                                    $virgilPrivateKey->getIdentifier());
                        } else {
                            throw new VirgilCryptoException("signAndEncrypt is supported only for strings");
                        }

                        $cipher->startEncryption();
                        break;

                    case $signingMode::SIGN_THEN_ENCRYPT():

                        $cipher->useSignerHash(new Sha512());
                        $cipher->addSigner($virgilPrivateKey->getIdentifier(), $virgilPrivateKey->getPrivateKey());

                        $size = null;


                         if (is_string($inputOutput)) {

                                $size = strlen($inputOutput);

                         } else if ($inputOutput instanceof StreamInterface) {

                                if (!$inputOutput->getStreamSize()) {
                                    $error = "signThenEncrypt for streams with unknown size is not supported";
                                    throw new VirgilCryptoException($error);
                                }

                                $size = $inputOutput->getStreamSize();
                        } else {
                            throw new VirgilCryptoException("Unsupported inputOutput type");
                        }

                        $cipher->startSignedEncryption($size);
                        break;
                }

            } else {
                $cipher->startEncryption();
            }

        } catch (Exception $e) {
            print($e);
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param $inputOutput
     * @param SigningOptions|null $signingOptions
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    private function processEncryption(RecipientCipher $cipher, $inputOutput, SigningOptions $signingOptions = null)
    {
        try {
            $result = null;

            if (is_string($inputOutput)) {
                    $result = $cipher->packMessageInfo();
                    $result .= $cipher->processEncryption($inputOutput);
                    $result .= $cipher->finishEncryption();

                    if (($signingOptions) && ($signingOptions->getSigningMode() == SigningMode::SIGN_THEN_ENCRYPT())) {
                        $result .= $cipher->packMessageInfoFooter();
                    }


            } else if ($inputOutput instanceof StreamInterface) {
                    $inputOutput->getOutputStream()->write($cipher->packMessageInfo());

                    $chunkClosure = function ($chunk) use ($cipher) { return $cipher->processEncryption($chunk); };
                    StreamService::forEachChunk($inputOutput, $chunkClosure, true);

                    $inputOutput->getOutputStream()->write($cipher->finishEncryption());

                    if ($signingOptions && ($signingOptions->getSigningMode() == SigningMode::SIGN_THEN_ENCRYPT())) {
                        $inputOutput->getOutputStream()->write($cipher->packMessageInfoFooter());
                    }
            } else {
                throw new VirgilCryptoException("Unsupported inputOutput type");
            }

            return $result;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param $inputOutput
     * @param VirgilPublicKeyCollection $recipients
     * @param SigningOptions|null $signingOptions
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function encrypt($inputOutput, VirgilPublicKeyCollection $recipients, SigningOptions $signingOptions = null)
    {
        try {

            $aesGcm = new Aes256Gcm();
            $cipher = new RecipientCipher();

            $cipher->useEncryptionCipher($aesGcm);
            $cipher->useRandom($this->getRandom());

            foreach ($recipients->getAsArray() as $recipient) {
                $cipher->addKeyRecipient($recipient->getIdentifier(), $recipient->getPublicKey());
            }

            $this->startEncryption($cipher, $inputOutput, $signingOptions);

            return $this->processEncryption($cipher, $inputOutput, $signingOptions);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param $inputOutput
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    private function processDecryption(RecipientCipher $cipher, $inputOutput)
    {
        try {

            $result = null;

            if (is_string($inputOutput)) {
                $result = $cipher->processDecryption($inputOutput);
                $result .= $cipher->finishDecryption();


            } else if ($inputOutput instanceof StreamInterface) {
                $chunkClosure = function ($chunk) use ($cipher) { return $cipher->processDecryption($chunk); };

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
     * @return bool
     * @throws VirgilCryptoException
     */
    private function verifyPlainSignature(RecipientCipher $cipher, $inputOutput, string $result = null,
                                          VirgilPublicKeyCollection $publicKeys): bool
    {
        try {
            $signerPublicKey = null;

            if ($inputOutput instanceof StreamInterface)
                throw new VirgilCryptoException("signAndEncrypt is not supported for streams");

            if (1 == $publicKeys->getAmountOfKeys()) {
                $signerPublicKey = $publicKeys->getFirst();

            } else {
                $signerId = $cipher->customParams()->findData(self::CUSTOM_PARAM_KEY_SIGNER_ID);

                if (!$signerId)
                    throw new VirgilCryptoException(VirgilCryptoError::SIGNER_NOT_FOUND());

                foreach ($publicKeys->getAsArray() as $publicKey) {
                    if ($publicKey->getIdentifier() == $signerId) {
                        $signerPublicKey = $publicKey;
                        break;
                    }
                }

                if (!$signerPublicKey)
                    throw new VirgilCryptoException(VirgilCryptoError::SIGNER_NOT_FOUND());
            }

            $signature = $cipher->customParams()->findData(self::CUSTOM_PARAM_KEY_SIGNATURE);

            if (!$signature)
                throw new VirgilCryptoException(VirgilCryptoError::SIGNATURE_NOT_FOUND());

            $result = $this->verifySignature($signature, $result, $signerPublicKey);

            if (!$result)
                throw new VirgilCryptoException(VirgilCryptoError::SIGNATURE_NOT_VERIFIED());

            return true;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param VirgilPublicKeyCollection $publicKeys
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    private function verifyEncryptedSignature(RecipientCipher $cipher, VirgilPublicKeyCollection $publicKeys): bool
    {
        try {
            $signerPublicKey = null;

            if (!$cipher->isDataSigned())
                throw new VirgilCryptoException(VirgilCryptoError::DATA_IS_NOT_SIGNED());

            $signerInfoList = $cipher->signerInfos();

            $res = ($signerInfoList->hasItem() && !$signerInfoList->hasNext());
            if (!$res)
                throw new VirgilCryptoException(VirgilCryptoError::DATA_IS_NOT_SIGNED());

            $signerInfo = $signerInfoList->item();

            foreach ($publicKeys->getAsArray() as $publicKey) {
                if ($publicKey->getIdentifier() == $signerInfo->signerId()) {
                    $signerPublicKey = $publicKey->getPublicKey();
                    break;
                }
            }

            if (!$signerPublicKey)
                throw new VirgilCryptoException(VirgilCryptoError::SIGNER_NOT_FOUND());

            $result = $cipher->verifySignerInfo($signerInfo, $signerPublicKey);

            if (!$result)
                throw new VirgilCryptoException(VirgilCryptoError::SIGNATURE_NOT_VERIFIED());

            return true;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param $inputOutput
     * @param string|null $result
     * @param VerifyingOptions|null $verifyingOptions
     *
     * @throws VirgilCryptoException
     */
    private function finishDecryption(RecipientCipher $cipher, $inputOutput, string $result = null,
                                      VerifyingOptions $verifyingOptions = null): void
    {
        try {

            if ($verifyingOptions) {

                $mode = $verifyingOptions->getVerifyingMode();

                if ($mode === VerifyingMode::ANY()) {
                    $mode = $cipher->isDataSigned() ? VerifyingMode::DECRYPT_THEN_VERIFY(
                    ) : VerifyingMode::DECRYPT_AND_VERIFY();
                }

                $publicKeys = $verifyingOptions->getVirgilPublicKeys();
                switch ($mode) {
                    case VerifyingMode::DECRYPT_AND_VERIFY():
                        $this->verifyPlainSignature($cipher,  $inputOutput, $result, $publicKeys);
                        break;

                    case VerifyingMode::DECRYPT_THEN_VERIFY():
                        $this->verifyEncryptedSignature($cipher, $publicKeys);
                        break;
                }

            } else {
                return;
            }

        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
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

            $chunkClosure = function ($chunk) use ($signer) { $signer->appendData($chunk); };
            StreamService::forEachChunk($stream, $chunkClosure, false);

            return $signer->sign($virgilPrivateKey->getPrivateKey());

        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
    }

    /**
     * Verifies digital signature of data stream
     * - Note: Verification algorithm depends on PublicKey type. Default: EdDSA
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
    ): bool
    {
        try {
            $verifier = new Verifier();

            $verifier->reset($signature);

            $chunkClosure = function ($chunk) use ($verifier) { $verifier->appendData($chunk); };
            StreamService::forEachChunk($inputStream, $chunkClosure, false);

            return $verifier->verify($virgilPublicKey->getPublicKey());

        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
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
        switch ($algorithm) {
            case $algorithm::SHA224():
                $hash = new Sha224();
                break;
            case $algorithm::SHA256():
                $hash = new Sha256();
                break;
            case $algorithm::SHA384():
                $hash = new Sha384();
                break;
            case $algorithm::SHA512():
                $hash = new Sha512();
                break;
            default:
                $hash = new Sha512();
        }

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
     * Signs (with private key) Then Encrypts data / stream (and signature) for passed PublicKeys
     * 1. Generates signature depending on KeyType
     * 2. Generates random AES-256 KEY1
     * 3. Encrypts data with KEY1 using AES-256-GCM and generates signature
     * 4. Encrypts signature with KEY1 using AES-256-GCM
     * 5. Generates ephemeral key pair for each recipient
     * 6. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
     * 7. Computes KDF to obtain AES-256 key from shared secret for each recipient
     * 8. Encrypts KEY1 with this key using AES-256-CBC for each recipient
     *
     * @param $inputOutput
     * @param VirgilPrivateKey $privateKey
     * @param VirgilPublicKeyCollection $recipients
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function authEncrypt(
        $inputOutput,
        VirgilPrivateKey $privateKey,
        VirgilPublicKeyCollection $recipients
    ): ?string
    {
        try {
            $signingOptions = new SigningOptions($privateKey, SigningMode::SIGN_THEN_ENCRYPT());
            return $this->encrypt($inputOutput, $recipients, $signingOptions);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e);
        }
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
    public function authDecrypt($inputOutput, VirgilPrivateKey $privateKey, VirgilPublicKeyCollection $recipients,
                                bool $allowNotEncryptedSignature = false): ?string
    {
        try {
            $verifyMode = $allowNotEncryptedSignature ? VerifyingMode::ANY() : VerifyingMode::DECRYPT_THEN_VERIFY();
            $verifyingOptions = new VerifyingOptions($recipients, $verifyMode);

            return $this->decrypt($inputOutput, $privateKey, $verifyingOptions);

        } catch (Exception $e) {
            if ($e instanceof VirgilCryptoException)
                throw $e;

            throw new VirgilCryptoException($e);
        }
    }
}
