/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import de.rub.nds.sshattacker.core.crypto.keys.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;

import java.math.BigInteger;

public class XCurveEcdhKeyExchange extends DhBasedKeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    private final NamedGroup group;

    private CustomKeyPair<XCurveEcPrivateKey, XCurveEcPublicKey> localKeyPair;
    private XCurveEcPublicKey remotePublicKey;

    public XCurveEcdhKeyExchange(NamedGroup group) {
        super();
        if (!group.isRFC7748Curve()) {
            throw new IllegalArgumentException("XCurveEcdhKeyExchange does not support named group " + group);
        }
        this.group = group;
        precompute();
    }

    private void precompute() {
        if (group == NamedGroup.ECDH_X25519) {
            X25519.precompute();
        } else {
            X448.precompute();
        }
    }

    public static XCurveEcdhKeyExchange newInstance(KeyExchangeAlgorithm negotiatedKexAlgorithm) {
        NamedGroup group;
        switch (negotiatedKexAlgorithm) {
            case CURVE25519_SHA256:
            case CURVE25519_SHA256_LIBSSH_ORG:
                group = NamedGroup.ECDH_X25519;
                break;
            case CURVE448_SHA512:
                group = NamedGroup.ECDH_X448;
                break;
            default:
                // TODO: Determine, whether throwing and error or continuing with a predetermined curve is better
                LOGGER.warn("Initializing a new XEcdhKeyExchange without an RFC7748 ECDH key exchange algorithm negotiated. Falling back to curve25519-sha256.");
                group = NamedGroup.ECDH_X25519;
                break;
        }
        return new XCurveEcdhKeyExchange(group);
    }

    @Override
    public void generateLocalKeyPair() {
        byte[] privateKeyBytes;
        byte[] publicKeyBytes;
        if (group == NamedGroup.ECDH_X25519) {
            privateKeyBytes = new byte[CryptoConstants.X25519_POINT_SIZE];
            X25519.generatePrivateKey(random, privateKeyBytes);
            publicKeyBytes = new byte[CryptoConstants.X25519_POINT_SIZE];
            X25519.generatePublicKey(privateKeyBytes, 0, publicKeyBytes, 0);
        } else {
            privateKeyBytes = new byte[CryptoConstants.X448_POINT_SIZE];
            X448.generatePrivateKey(random, privateKeyBytes);
            publicKeyBytes = new byte[CryptoConstants.X448_POINT_SIZE];
            X448.generatePublicKey(privateKeyBytes, 0, publicKeyBytes, 0);
        }
        XCurveEcPrivateKey privateKey = new XCurveEcPrivateKey(privateKeyBytes, group);
        XCurveEcPublicKey publicKey = new XCurveEcPublicKey(publicKeyBytes, group);
        this.localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes) {
        byte[] publicKeyBytes;
        if (group == NamedGroup.ECDH_X25519) {
            publicKeyBytes = new byte[CryptoConstants.X25519_POINT_SIZE];
            X25519.generatePublicKey(privateKeyBytes, 0, publicKeyBytes, 0);
        } else {
            publicKeyBytes = new byte[CryptoConstants.X448_POINT_SIZE];
            X448.generatePublicKey(privateKeyBytes, 0, publicKeyBytes, 0);
        }
        XCurveEcPrivateKey privateKey = new XCurveEcPrivateKey(privateKeyBytes, group);
        XCurveEcPublicKey publicKey = new XCurveEcPublicKey(publicKeyBytes, group);
        this.localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        XCurveEcPrivateKey privateKey = new XCurveEcPrivateKey(privateKeyBytes, group);
        XCurveEcPublicKey publicKey = new XCurveEcPublicKey(publicKeyBytes, group);
        this.localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setRemotePublicKey(byte[] publicKeyBytes) {
        this.remotePublicKey = new XCurveEcPublicKey(publicKeyBytes, group);
    }

    @Override
    public void computeSharedSecret() {
        byte[] sharedBytes;
        if (group == NamedGroup.ECDH_X25519) {
            sharedBytes = new byte[CryptoConstants.X25519_POINT_SIZE];
            X25519.scalarMult(localKeyPair.getPrivate().getScalar(), 0, remotePublicKey.getCoordinate(), 0,
                    sharedBytes, 0);
        } else {
            sharedBytes = new byte[CryptoConstants.X448_POINT_SIZE];
            X448.scalarMult(localKeyPair.getPrivate().getScalar(), 0, remotePublicKey.getCoordinate(), 0, sharedBytes,
                    0);
        }
        sharedSecret = new BigInteger(sharedBytes);
        LOGGER.debug("Finished computation of shared secret: "
                + ArrayConverter.bytesToRawHexString(sharedSecret.toByteArray()));
    }

    @Override
    public CustomKeyPair<XCurveEcPrivateKey, XCurveEcPublicKey> getLocalKeyPair() {
        return localKeyPair;
    }

    @Override
    public XCurveEcPublicKey getRemotePublicKey() {
        return remotePublicKey;
    }

}
