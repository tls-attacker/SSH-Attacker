/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;

public class XCurveEcdhKeyExchange extends AbstractEcdhKeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    private CustomKeyPair<XCurveEcPrivateKey, XCurveEcPublicKey> localKeyPair;
    private XCurveEcPublicKey remotePublicKey;
    private final boolean encodeSharedBytes;

    public XCurveEcdhKeyExchange(NamedEcGroup group, boolean encodeSharedBytes) {
        super(group);
        this.encodeSharedBytes = encodeSharedBytes;
        if (!group.isRFC7748Curve()) {
            throw new IllegalArgumentException(
                    "XCurveEcdhKeyExchange does not support named group " + group);
        }
        precompute();
    }

    private void precompute() {
        if (group == NamedEcGroup.CURVE25519) {
            X25519.precompute();
        } else {
            X448.precompute();
        }
    }

    @Override
    public void generateLocalKeyPair() {
        byte[] privateKeyBytes;
        byte[] publicKeyBytes;
        if (group == NamedEcGroup.CURVE25519) {
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
        localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes) {
        byte[] publicKeyBytes;
        if (group == NamedEcGroup.CURVE25519) {
            publicKeyBytes = new byte[CryptoConstants.X25519_POINT_SIZE];
            X25519.generatePublicKey(privateKeyBytes, 0, publicKeyBytes, 0);
        } else {
            publicKeyBytes = new byte[CryptoConstants.X448_POINT_SIZE];
            X448.generatePublicKey(privateKeyBytes, 0, publicKeyBytes, 0);
        }
        XCurveEcPrivateKey privateKey = new XCurveEcPrivateKey(privateKeyBytes, group);
        XCurveEcPublicKey publicKey = new XCurveEcPublicKey(publicKeyBytes, group);
        localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        XCurveEcPrivateKey privateKey = new XCurveEcPrivateKey(privateKeyBytes, group);
        XCurveEcPublicKey publicKey = new XCurveEcPublicKey(publicKeyBytes, group);
        localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setRemotePublicKey(byte[] publicKeyBytes) {
        remotePublicKey = new XCurveEcPublicKey(publicKeyBytes, group);
    }

    @Override
    public void computeSharedSecret() throws CryptoException {
        if (localKeyPair == null || remotePublicKey == null) {
            throw new CryptoException(
                    "Unable to compute shared secret - either local key pair or remote public key is null");
        }
        byte[] sharedBytes;
        if (group == NamedEcGroup.CURVE25519) {
            sharedBytes = new byte[CryptoConstants.X25519_POINT_SIZE];
            X25519.scalarMult(
                    localKeyPair.getPrivateKey().getScalar(),
                    0,
                    remotePublicKey.getCoordinate(),
                    0,
                    sharedBytes,
                    0);
        } else {
            sharedBytes = new byte[CryptoConstants.X448_POINT_SIZE];
            X448.scalarMult(
                    localKeyPair.getPrivateKey().getScalar(),
                    0,
                    remotePublicKey.getCoordinate(),
                    0,
                    sharedBytes,
                    0);
        }
        sharedSecret =
                encodeSharedBytes ? new BigInteger(1, sharedBytes).toByteArray() : sharedBytes;
        LOGGER.debug(
                "Finished computation of shared secret: {}",
                () -> ArrayConverter.bytesToRawHexString(sharedSecret));
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
