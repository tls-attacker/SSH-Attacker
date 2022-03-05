/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.NamedDHGroup;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDhPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchange extends DhBasedKeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    private BigInteger modulus;
    private BigInteger generator;

    private CustomKeyPair<CustomDhPrivateKey, CustomDhPublicKey> localKeyPair;
    private CustomDhPublicKey remotePublicKey;

    public DhKeyExchange() {
        super();
    }

    public DhKeyExchange(NamedDHGroup group) {
        super();
        this.modulus = group.getModulus();
        this.generator = group.getGenerator();
    }

    public static DhKeyExchange newInstance(KeyExchangeAlgorithm negotiatedKexAlgorithm) {
        NamedDHGroup group;
        switch (negotiatedKexAlgorithm) {
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1:
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256:
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA224_SSH_COM:
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA384_SSH_COM:
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA512_SSH_COM:
                return new DhKeyExchange();
            case DIFFIE_HELLMAN_GROUP1_SHA1:
                group = NamedDHGroup.GROUP1;
                break;
            case DIFFIE_HELLMAN_GROUP14_SHA1:
            case DIFFIE_HELLMAN_GROUP14_SHA256:
            case DIFFIE_HELLMAN_GROUP14_SHA224_SSH_COM:
            case DIFFIE_HELLMAN_GROUP14_SHA256_SSH_COM:
                group = NamedDHGroup.GROUP14;
                break;
            case DIFFIE_HELLMAN_GROUP15_SHA512:
            case DIFFIE_HELLMAN_GROUP15_SHA256_SSH_COM:
            case DIFFIE_HELLMAN_GROUP15_SHA384_SSH_COM:
                group = NamedDHGroup.GROUP15;
                break;
            case DIFFIE_HELLMAN_GROUP16_SHA512:
            case DIFFIE_HELLMAN_GROUP16_SHA384_SSH_COM:
            case DIFFIE_HELLMAN_GROUP16_SHA512_SSH_COM:
                group = NamedDHGroup.GROUP16;
                break;
            case DIFFIE_HELLMAN_GROUP17_SHA512:
                group = NamedDHGroup.GROUP17;
                break;
            case DIFFIE_HELLMAN_GROUP18_SHA512:
            case DIFFIE_HELLMAN_GROUP18_SHA512_SSH_COM:
                group = NamedDHGroup.GROUP18;
                break;
            default:
                // TODO: Determine, whether throwing an error or continuing with a predetermined
                // group is better
                LOGGER.warn(
                        "Initializing a new DHKeyExchange without an DH key exchange algorithm negotiated, falling back to group 14");
                group = NamedDHGroup.GROUP14;
                break;
        }
        return new DhKeyExchange(group);
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public BigInteger getGenerator() {
        return generator;
    }

    public void setGenerator(BigInteger generator) {
        this.generator = generator;
    }

    public CustomKeyPair<CustomDhPrivateKey, CustomDhPublicKey> getLocalKeyPair() {
        return localKeyPair;
    }

    public CustomDhPublicKey getRemotePublicKey() {
        return remotePublicKey;
    }

    public void setRemotePublicKey(byte[] publicKey) {
        setRemotePublicKey(new BigInteger(publicKey));
    }

    public void setRemotePublicKey(BigInteger publicKey) {
        this.remotePublicKey = new CustomDhPublicKey(modulus, generator, publicKey);
    }

    public boolean areGroupParametersSet() {
        return modulus != null && generator != null;
    }

    public void generateLocalKeyPair() {
        if (modulus == null || generator == null) {
            throw new RuntimeException(
                    "Unable to generate local key pair without specifying the diffie hellman group first!");
        }
        int privateKeyBitLength = modulus.bitLength();
        BigInteger pMinusOne = modulus.subtract(BigInteger.ONE);
        CustomDhPrivateKey privateKey;
        do {
            privateKey =
                    new CustomDhPrivateKey(
                            modulus,
                            generator,
                            new BigInteger(privateKeyBitLength, random).mod(modulus));
        } while (privateKey.getX().equals(BigInteger.ZERO)
                || privateKey.getX().equals(BigInteger.ONE)
                || privateKey.getX().equals(pMinusOne));
        CustomDhPublicKey publicKey =
                new CustomDhPublicKey(
                        modulus, generator, generator.modPow(privateKey.getX(), modulus));
        this.localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes) {
        BigInteger privateKeyExponent = new BigInteger(privateKeyBytes);
        CustomDhPrivateKey privateKey =
                new CustomDhPrivateKey(modulus, generator, privateKeyExponent);
        CustomDhPublicKey publicKey =
                new CustomDhPublicKey(
                        modulus, generator, generator.modPow(privateKey.getX(), modulus));
        this.localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        CustomDhPrivateKey privateKey =
                new CustomDhPrivateKey(modulus, generator, new BigInteger(privateKeyBytes));
        CustomDhPublicKey publicKey =
                new CustomDhPublicKey(modulus, generator, new BigInteger(publicKeyBytes));
        this.localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void computeSharedSecret() {
        sharedSecret = remotePublicKey.getY().modPow(localKeyPair.getPrivate().getX(), modulus);
        LOGGER.debug(
                "Finished computation of shared secret: "
                        + ArrayConverter.bytesToRawHexString(sharedSecret.toByteArray()));
    }
}
