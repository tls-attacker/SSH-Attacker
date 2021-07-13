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
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import de.rub.nds.sshattacker.core.crypto.ec.*;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

public class EcdhKeyExchange extends DhBasedKeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    private final NamedGroup group;
    private final EllipticCurve ellipticCurve;

    private CustomKeyPair<CustomEcPrivateKey, CustomEcPublicKey> localKeyPair;
    private CustomEcPublicKey remotePublicKey;

    public EcdhKeyExchange(NamedGroup group) {
        super();
        if (!group.isStandardCurve()) {
            throw new IllegalArgumentException("EcdhKeyExchange does not support named group " + group);
        }
        this.group = group;
        this.ellipticCurve = CurveFactory.getCurve(group);
    }

    public static EcdhKeyExchange newInstance(KeyExchangeAlgorithm negotiatedKexAlgorithm) {
        NamedGroup group;
        switch (negotiatedKexAlgorithm) {
            case ECDH_SHA2_NISTP256:
                group = NamedGroup.SECP256R1;
                break;
            case ECDH_SHA2_NISTP384:
                group = NamedGroup.SECP384R1;
                break;
            case ECDH_SHA2_NISTP521:
                group = NamedGroup.SECP521R1;
                break;
            default:
                String[] kexParts = negotiatedKexAlgorithm.name().split("_");
                if (!kexParts[0].equals("ECDH")) {
                    // TODO: Determine, whether throwing and error or continuing with a predetermined curve is better
                    LOGGER.warn("Initializing a new ECDHKeyExchange without an ECDH key exchange algorithm negotiated. Falling back to ecdh-sha2-nistp256.");
                    group = NamedGroup.SECP256R1;
                } else {
                    group = NamedGroup.valueOf(kexParts[3]);
                }
                break;
        }
        return new EcdhKeyExchange(group);
    }

    @Override
    public void generateLocalKeyPair() {
        int privateKeyBitLength = ellipticCurve.getBasePointOrder().bitLength();
        CustomEcPrivateKey privateKey;
        do {
            privateKey = new CustomEcPrivateKey(new BigInteger(privateKeyBitLength, random).mod(ellipticCurve
                    .getBasePointOrder()), group);
        } while (privateKey.getS().equals(BigInteger.ZERO));
        Point publicKeyPoint = ellipticCurve.mult(privateKey.getS(), ellipticCurve.getBasePoint());
        CustomEcPublicKey publicKey = new CustomEcPublicKey(publicKeyPoint, group);
        this.localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes) {
        BigInteger privateKeyScalar = new BigInteger(privateKeyBytes);
        Point publicKeyPoint = ellipticCurve.mult(privateKeyScalar, ellipticCurve.getBasePoint());
        CustomEcPrivateKey privateKey = new CustomEcPrivateKey(privateKeyScalar, group);
        CustomEcPublicKey publicKey = new CustomEcPublicKey(publicKeyPoint, group);
        this.localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        BigInteger privateKeyScalar = new BigInteger(privateKeyBytes);
        Point publicKeyPoint = PointFormatter.formatFromByteArray(group, publicKeyBytes);
        CustomEcPrivateKey privateKey = new CustomEcPrivateKey(privateKeyScalar, group);
        CustomEcPublicKey publicKey = new CustomEcPublicKey(publicKeyPoint, group);
        this.localKeyPair = new CustomKeyPair<>(privateKey, publicKey);
    }

    @Override
    public void setRemotePublicKey(byte[] serializedPublicKey) {
        Point publicKeyPoint = PointFormatter.formatFromByteArray(group, serializedPublicKey);
        this.remotePublicKey = new CustomEcPublicKey(publicKeyPoint, group);
    }

    @Override
    public void computeSharedSecret() {
        Point sharedPoint = ellipticCurve.mult(localKeyPair.getPrivate().getS(), remotePublicKey.getWAsPoint());
        sharedSecret = sharedPoint.getFieldX().getData();
        LOGGER.debug("Finished computation of shared secret: "
                + ArrayConverter.bytesToRawHexString(sharedSecret.toByteArray()));
    }

    @Override
    public CustomKeyPair<CustomEcPrivateKey, CustomEcPublicKey> getLocalKeyPair() {
        return localKeyPair;
    }

    @Override
    public CustomEcPublicKey getRemotePublicKey() {
        return remotePublicKey;
    }
}
