/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.crypto.ec.*;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchange
        extends AbstractEcdhKeyExchange<CustomEcPrivateKey, CustomEcPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final EllipticCurve ellipticCurve;

    protected EcdhKeyExchange(NamedEcGroup group) {
        super(group);
        if (group.isRFC7748Curve()) {
            throw new IllegalArgumentException(
                    "EcdhKeyExchange does not support named group " + group);
        }
        ellipticCurve = CurveFactory.getCurve(group);
    }

    @Override
    public void generateKeyPair() {
        int privateKeyBitLength = ellipticCurve.getBasePointOrder().bitLength();
        CustomEcPrivateKey privateKey;
        do {
            privateKey =
                    new CustomEcPrivateKey(
                            new BigInteger(privateKeyBitLength, random)
                                    .mod(ellipticCurve.getBasePointOrder()),
                            group);
        } while (privateKey.getS().equals(BigInteger.ZERO));
        Point publicKeyPoint = ellipticCurve.mult(privateKey.getS(), ellipticCurve.getBasePoint());
        CustomEcPublicKey publicKey = new CustomEcPublicKey(publicKeyPoint, group);
        localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] encodedPrivateKey) {
        BigInteger privateKeyScalar = new BigInteger(encodedPrivateKey);
        Point publicKeyPoint = ellipticCurve.mult(privateKeyScalar, ellipticCurve.getBasePoint());
        CustomEcPrivateKey privateKey = new CustomEcPrivateKey(privateKeyScalar, group);
        CustomEcPublicKey publicKey = new CustomEcPublicKey(publicKeyPoint, group);
        localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] encodedPrivateKey, byte[] encodedPublicKey) {
        BigInteger privateKeyScalar = new BigInteger(encodedPrivateKey);
        Point publicKeyPoint = PointFormatter.formatFromByteArray(group, encodedPublicKey);
        CustomEcPrivateKey privateKey = new CustomEcPrivateKey(privateKeyScalar, group);
        CustomEcPublicKey publicKey = new CustomEcPublicKey(publicKeyPoint, group);
        localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setRemotePublicKey(byte[] encodedPublicKey) {
        Point publicKeyPoint = PointFormatter.formatFromByteArray(group, encodedPublicKey);
        remotePublicKey = new CustomEcPublicKey(publicKeyPoint, group);
    }

    @Override
    public void computeSharedSecret() throws CryptoException {
        if (localKeyPair == null || remotePublicKey == null) {
            throw new CryptoException(
                    "Unable to compute shared secret - either local key pair or remote public key is null");
        }
        Point sharedPoint =
                ellipticCurve.mult(
                        localKeyPair.getPrivateKey().getS(),
                        ((CustomEcPublicKey) remotePublicKey).getWAsPoint());
        // RFC 5656 defines ECDH with cofactor multiplication as the cryptographic primitive
        sharedPoint = ellipticCurve.mult(ellipticCurve.getCofactor(), sharedPoint);
        sharedSecret = sharedPoint.getFieldX().getData().toByteArray();
        LOGGER.debug(
                "Finished computation of shared secret: {}",
                ArrayConverter.bytesToRawHexString(sharedSecret));
    }
}
