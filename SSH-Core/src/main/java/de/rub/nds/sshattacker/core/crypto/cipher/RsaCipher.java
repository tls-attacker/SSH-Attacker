/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.util.RsaPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;


public class RsaCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeyExchangeAlgorithm keyExchangeAlgorithm;

    private RsaPublicKey rsaPublicKey;

    private Cipher encryptionCipher;

    private Signature verificationSignature;

    public RsaCipher(KeyExchangeAlgorithm keyExchangeAlgorithm, RsaPublicKey rsaPublicKey) {
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
        this.rsaPublicKey = rsaPublicKey;
        prepareCiphers();
    }

    public RsaPublicKey getRsaPublicKey() {
        return rsaPublicKey;
    }

    public void setRsaPublicKey(RsaPublicKey rsaPublicKey) {
        this.rsaPublicKey = rsaPublicKey;
    }

    public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        return keyExchangeAlgorithm;
    }

    public void setKeyExchangeAlgorithm(KeyExchangeAlgorithm keyExchangeAlgorithm) {
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    public byte[] encrypt(byte[] data) throws CryptoException {
        try {
            return encryptionCipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Could not encrypt data with RSA.", e);
        }
    }

    public boolean verifySignature(byte[] data, byte[] signature) throws CryptoException {
        try {
            verificationSignature.update(data);
            return verificationSignature.verify(signature);
        } catch (SignatureException e) {
            throw new CryptoException("Signature verification with RSA failed.", e);
        }
    }

    private void prepareCiphers() {
        String cipherInstanceName;
        String signatureInstanceName;
        String hashFunctionName;
        String maskGenerationFunctionName;

        switch (keyExchangeAlgorithm) {
            case RSA1024_SHA1:
                cipherInstanceName = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
                signatureInstanceName = "SHA1withRSA";
                hashFunctionName = "SHA-1";
                maskGenerationFunctionName = "MGF1";
                break;
            case RSA2048_SHA256:
                cipherInstanceName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
                signatureInstanceName = "SHA256withRSA";
                hashFunctionName = "SHA-256";
                maskGenerationFunctionName = "MGF1";
                break;
            default:
                throw new IllegalStateException("Unexpected value for key exchange: " + keyExchangeAlgorithm);
        }

        if (rsaPublicKey != null) {
            prepareEncryptionCipher(cipherInstanceName, hashFunctionName, maskGenerationFunctionName);
            prepareVerificationSignature(signatureInstanceName);
        } else {
            LOGGER.warn("Could not create encryption cipher, because the RSA public key is not set.");
        }
    }

    private void prepareEncryptionCipher(String instanceName, String hashFunction, String maskGenerationFunction) {
        try {
            Cipher cipher;
            cipher = Cipher.getInstance(instanceName);
            OAEPParameterSpec spec = new OAEPParameterSpec(hashFunction, maskGenerationFunction,
                    new MGF1ParameterSpec(hashFunction), PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey, spec);
            encryptionCipher = cipher;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            LOGGER.error("RSA Encryption Cipher creation failed with error: " + e);
        }
    }

    private void prepareVerificationSignature(String instanceName) {
        try {
            Signature signature;
            signature = Signature.getInstance(instanceName);
            signature.initVerify(rsaPublicKey);
            verificationSignature = signature;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            LOGGER.error("RSA Encryption Cipher creation failed with error: " + e);
        }
    }
}
