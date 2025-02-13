/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.cipher.AbstractCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
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

public class RsaKeyExchange extends KeyEncapsulation<CustomRsaPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    private CustomRsaPrivateKey privateKey;

    private final int publicKeySize;
    private final HashFunction hashFunction;

    protected RsaKeyExchange(int publicKeySize, HashFunction hashFunction) {
        super();
        this.publicKeySize = publicKeySize;
        this.hashFunction = hashFunction;
    }

    public static RsaKeyExchange newInstance(SshContext context, KeyExchangeAlgorithm algorithm) {
        if (algorithm == null || algorithm.getFlowType() != KeyExchangeFlowType.RSA) {
            algorithm = context.getConfig().getDefaultRsaKeyExchangeAlgorithm();
            LOGGER.warn(
                    "Trying to instantiate a new RSA key exchange without a matching key exchange algorithm negotiated, falling back to {}",
                    algorithm);
        }
        return switch (algorithm) {
            case RSA1024_SHA1 -> new RsaKeyExchange(1024, HashFunction.SHA1);
            case RSA2048_SHA256 -> new RsaKeyExchange(2048, HashFunction.SHA256);
            default ->
                    throw new IllegalArgumentException(
                            "Unable to create a new RSA key exchange instance - provided algorithm is not of flow type RSA");
        };
    }

    @Override
    public void generateKeyPair() throws CryptoException {
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(
                    "Unable to generate RSA transient key - RSA key pair generator is not available");
        }
        keyGen.initialize(publicKeySize);
        KeyPair transientKeyPair = keyGen.generateKeyPair();
        privateKey = new CustomRsaPrivateKey((RSAPrivateKey) transientKeyPair.getPrivate());
        publicKey = new CustomRsaPublicKey((RSAPublicKey) transientKeyPair.getPublic());
    }

    public CustomRsaPrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(CustomRsaPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    @Override
    public void encapsulate() throws CryptoException {
        if (sharedSecret == null) {
            // 0 <= K < 2^(KLEN-2*HLEN-49)
            int maximumBits = publicKeySize - 2 * hashFunction.getOutputSize() - 49;
            sharedSecret = new BigInteger(maximumBits, random).toByteArray();
        }
        AbstractCipher cipher = CipherFactory.getOaepCipher(hashFunction, publicKey);
        byte[] encodedSharedSecret = Converter.byteArrayToMpint(sharedSecret);
        encapsulation = cipher.encrypt(encodedSharedSecret);
    }

    @Override
    public void decapsulate() throws CryptoException {
        if (privateKey == null || encapsulation == null) {
            throw new CryptoException(
                    "Unable to decapsulate - either private key or encapsulation is null");
        }
        AbstractCipher cipher = CipherFactory.getOaepCipher(hashFunction, privateKey);
        byte[] decryptedSharedSecret = cipher.decrypt(encapsulation);
        int sharedSecretLength =
                ArrayConverter.bytesToInt(
                        Arrays.copyOfRange(
                                decryptedSharedSecret, 0, DataFormatConstants.MPINT_SIZE_LENGTH));
        sharedSecret =
                Arrays.copyOfRange(
                        decryptedSharedSecret,
                        DataFormatConstants.MPINT_SIZE_LENGTH,
                        DataFormatConstants.MPINT_SIZE_LENGTH + sharedSecretLength);
    }

    public BigInteger getExponent() {
        return publicKey.getPublicExponent();
    }

    public BigInteger getModulus() {
        return publicKey.getModulus();
    }

    public int getPublicKeySize() {
        return publicKeySize;
    }

    public HashFunction getHashFunction() {
        return hashFunction;
    }
}
