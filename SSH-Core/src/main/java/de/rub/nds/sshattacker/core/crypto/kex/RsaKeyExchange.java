/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchange extends KeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> transientKey;

    private final KeyExchangeAlgorithm algorithm;

    // HLEN in RFC 4432 (in bits)
    private int hashLength;

    private int transientKeyLength;

    private RsaKeyExchange(KeyExchangeAlgorithm algorithm) {
        this.algorithm = algorithm;
        switch (algorithm) {
            case RSA1024_SHA1:
                this.hashLength = 160;
                this.transientKeyLength = 1024;
                break;
            case RSA2048_SHA256:
                this.hashLength = 256;
                this.transientKeyLength = 2048;
                break;
            default:
                throw new IllegalArgumentException(
                        "Unable to create a new RSA key exchange instance - provided algorithm is not of flow type RSA");
        }
    }

    public static RsaKeyExchange newInstance(SshContext context, KeyExchangeAlgorithm algorithm) {
        if (algorithm == null || algorithm.getFlowType() != KeyExchangeFlowType.RSA) {
            algorithm = context.getConfig().getDefaultRsaKeyExchangeAlgorithm();
            LOGGER.warn(
                    "Trying to instantiate a new RSA key exchange without a matching key exchange algorithm negotiated, falling back to "
                            + algorithm);
        }
        return new RsaKeyExchange(algorithm);
    }

    @Override
    public void computeSharedSecret() {
        // Calculation of maximum number of bits taken from RFC 4432
        int maximumBits = (getModulusLengthInBits() - 2 * hashLength - 49);
        sharedSecret = new BigInteger(maximumBits, random);
    }

    public byte[] encryptSharedSecret() {
        EncryptionCipher cipher =
                CipherFactory.getEncryptionCipher(algorithm, transientKey.getPublicKey());
        try {
            // Shared secret is encrypted as a mpint (which includes an explicit length field)
            byte[] sharedSecretMpint = Converter.bigIntegerToMpint(sharedSecret);
            return cipher.encrypt(sharedSecretMpint);
        } catch (CryptoException e) {
            LOGGER.error("Unexpected cryptographic exception occurred while encrypting the secret");
            LOGGER.debug(e);
            return new byte[0];
        }
    }

    public void decryptSharedSecret(byte[] encryptedSharedSecret) throws CryptoException {
        if (transientKey.getPrivateKey().isEmpty()) {
            throw new CryptoException("Unable to decrypt shared secret - no private key present");
        }
        DecryptionCipher cipher =
                CipherFactory.getDecryptionCipher(algorithm, transientKey.getPrivateKey().get());
        try {
            byte[] decryptedSecretMpint = cipher.decrypt(encryptedSharedSecret);
            int sharedSecretLength =
                    ArrayConverter.bytesToInt(
                            Arrays.copyOfRange(
                                    decryptedSecretMpint,
                                    0,
                                    DataFormatConstants.MPINT_SIZE_LENGTH));
            this.sharedSecret =
                    new BigInteger(
                            Arrays.copyOfRange(
                                    decryptedSecretMpint,
                                    DataFormatConstants.MPINT_SIZE_LENGTH,
                                    DataFormatConstants.MPINT_SIZE_LENGTH + sharedSecretLength));
        } catch (CryptoException e) {
            LOGGER.error(
                    "Unexpected cryptographic exception occurred while decrypting the shared secret");
            LOGGER.debug(e);
            throw e;
        }
    }

    public void setTransientKey(
            SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> transientKey) {
        this.transientKey = transientKey;
    }

    public SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> getTransientKey() {
        return transientKey;
    }

    public void generateTransientKey() throws CryptoException {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(transientKeyLength);
            KeyPair key = keyGen.generateKeyPair();
            CustomRsaPublicKey publicKey = new CustomRsaPublicKey((RSAPublicKey) key.getPublic());
            CustomRsaPrivateKey privateKey =
                    new CustomRsaPrivateKey((RSAPrivateKey) key.getPrivate());
            this.transientKey = new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(
                    "Unable to generate RSA transient key - RSA key pair generator is not available");
        }
    }

    public BigInteger getExponent() {
        return transientKey.getPublicKey().getPublicExponent();
    }

    public BigInteger getModulus() {
        return transientKey.getPublicKey().getModulus();
    }

    public int getHashLength() {
        return hashLength;
    }

    public void setHashLength(int hashLength) {
        this.hashLength = hashLength;
    }

    public int getTransientKeyLength() {
        return transientKeyLength;
    }

    public void setTransientKeyLength(int transientKeyLength) {
        this.transientKeyLength = transientKeyLength;
    }

    private int getModulusLengthInBits() {
        if (transientKey != null) {
            return transientKey.getPublicKey().getModulus().bitLength();
        } else {
            // Fallback to default transient key length in case no actual transient key is present
            return transientKeyLength;
        }
    }

    public void setSharedSecret(BigInteger sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public boolean areParametersSet() {
        return transientKey != null && hashLength != 0;
    }
}
