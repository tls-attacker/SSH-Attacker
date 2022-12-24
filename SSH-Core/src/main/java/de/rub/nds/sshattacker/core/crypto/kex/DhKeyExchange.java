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
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.constants.NamedDhGroup;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDhPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Comparator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchange extends DhBasedKeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    private BigInteger modulus;
    private BigInteger generator;

    private CustomKeyPair<CustomDhPrivateKey, CustomDhPublicKey> localKeyPair;
    private CustomDhPublicKey remotePublicKey;

    protected DhKeyExchange() {
        super();
    }

    protected DhKeyExchange(NamedDhGroup group) {
        super();
        this.modulus = group.getModulus();
        this.generator = group.getGenerator();
    }

    public static DhKeyExchange newInstance(SshContext context, KeyExchangeAlgorithm algorithm) {
        if (algorithm == null
                || (algorithm.getFlowType() != KeyExchangeFlowType.DIFFIE_HELLMAN
                        && algorithm.getFlowType()
                                != KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE)) {
            algorithm = context.getConfig().getDefaultDhKeyExchangeAlgorithm();
            LOGGER.warn(
                    "Trying to instantiate a new DH or DH GEX key exchange without a matching key exchange algorithm negotiated, falling back to "
                            + algorithm);
        }
        /*
         * In case of group exchange algorithms the following group assignments can be seen as default values
         * which are used whenever the local key pair is being generated before a group has been negotiated.
         * This can be the case if, for example, SSH-Attacker tries to perform the actual key exchange prior to
         * group negotiation. The default values will be overwritten when negotiating a group.
         */
        NamedDhGroup group;
        switch (algorithm) {
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1:
            case DIFFIE_HELLMAN_GROUP1_SHA1:
                group = NamedDhGroup.GROUP1;
                break;
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256:
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA224_SSH_COM:
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA384_SSH_COM:
            case DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA512_SSH_COM:
            case DIFFIE_HELLMAN_GROUP14_SHA1:
            case DIFFIE_HELLMAN_GROUP14_SHA256:
            case DIFFIE_HELLMAN_GROUP14_SHA224_SSH_COM:
            case DIFFIE_HELLMAN_GROUP14_SHA256_SSH_COM:
                group = NamedDhGroup.GROUP14;
                break;
            case DIFFIE_HELLMAN_GROUP15_SHA512:
            case DIFFIE_HELLMAN_GROUP15_SHA256_SSH_COM:
            case DIFFIE_HELLMAN_GROUP15_SHA384_SSH_COM:
                group = NamedDhGroup.GROUP15;
                break;
            case DIFFIE_HELLMAN_GROUP16_SHA512:
            case DIFFIE_HELLMAN_GROUP16_SHA384_SSH_COM:
            case DIFFIE_HELLMAN_GROUP16_SHA512_SSH_COM:
                group = NamedDhGroup.GROUP16;
                break;
            case DIFFIE_HELLMAN_GROUP17_SHA512:
                group = NamedDhGroup.GROUP17;
                break;
            case DIFFIE_HELLMAN_GROUP18_SHA512:
            case DIFFIE_HELLMAN_GROUP18_SHA512_SSH_COM:
                group = NamedDhGroup.GROUP18;
                break;
            default:
                throw new NotImplementedException(
                        "Unable to create a new DH key exchange instance, key exchange algorithm "
                                + algorithm
                                + " is not yet implemented.");
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
    public void computeSharedSecret() throws CryptoException {
        if (localKeyPair == null || remotePublicKey == null) {
            throw new CryptoException(
                    "Unable to compute shared secret - either local key pair or remote public key is null");
        }
        sharedSecret =
                remotePublicKey
                        .getY()
                        .modPow(localKeyPair.getPrivate().getX(), modulus)
                        .toByteArray();
        LOGGER.debug(
                "Finished computation of shared secret: "
                        + ArrayConverter.bytesToRawHexString(sharedSecret));
    }

    public void selectGroup(int preferredGroupSize) {
        /*
         * Minimal group size taken from RFC 4419 Section 3:
         *   "In all cases, the size of the returned group SHOULD be at least 1024 bits."
         */
        this.selectGroup(1024, preferredGroupSize, Integer.MAX_VALUE);
    }

    public void selectGroup(int minimalGroupSize, int preferredGroupSize, int maximumGroupSize) {
        /*
         * Group selection based on the process described in RFC 4419:
         *
         *   The server should return the smallest group it knows that is larger
         *   than the size the client requested.  If the server does not know a
         *   group that is larger than the client request, then it SHOULD return
         *   the largest group it knows.  In all cases, the size of the returned
         *   group SHOULD be at least 1024 bits.
         */
        NamedDhGroup selectedGroup =
                Arrays.stream(NamedDhGroup.values())
                        .sorted(Comparator.comparingInt(group -> group.getModulus().bitLength()))
                        .filter(
                                (candidate) ->
                                        candidate.getModulus().bitLength() - preferredGroupSize
                                                >= 0)
                        .findFirst()
                        .orElseGet(
                                () ->
                                        Arrays.stream(NamedDhGroup.values())
                                                .max(
                                                        Comparator.comparingInt(
                                                                group ->
                                                                        group.getModulus()
                                                                                .bitLength()))
                                                .orElseThrow());
        if (selectedGroup.getModulus().bitLength() > maximumGroupSize) {
            LOGGER.info(
                    "DH GEX key exchange could not satisfy group size constraints reported by the remote peer: {} exceeds maximum group size of {} bits",
                    selectedGroup,
                    maximumGroupSize);
        }
        if (selectedGroup.getModulus().bitLength() < minimalGroupSize) {
            LOGGER.info(
                    "DH GEX key exchange could not satisfy group size constraints reported by the remote peer: {} falls behind minimal group size of {} bits",
                    selectedGroup,
                    minimalGroupSize);
        }
        LOGGER.info(
                "Selected DH group {} for key exchange, group size: {} bits (selected based on the preferred group size of {} bits)",
                selectedGroup,
                selectedGroup.getModulus().bitLength(),
                preferredGroupSize);
        this.setModulus(selectedGroup.getModulus());
        this.setGenerator(selectedGroup.getGenerator());
    }
}
