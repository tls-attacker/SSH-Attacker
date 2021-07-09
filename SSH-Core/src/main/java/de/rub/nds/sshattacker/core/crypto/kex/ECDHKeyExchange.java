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
import de.rub.nds.sshattacker.core.constants.ECPointFormat;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import de.rub.nds.sshattacker.core.crypto.ec.*;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class ECDHKeyExchange extends KeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    private NamedGroup namedGroup;
    private EllipticCurve ellipticCurve;
    private final SecureRandom random;

    private ECDHKeyPair localKeyPair;
    private ECDHKeyPair remotePublicKey;

    public ECDHKeyExchange(KeyExchangeAlgorithm negotiatedKeyExchange) {
        super(negotiatedKeyExchange);
        this.random = new SecureRandom();
        initCurve(negotiatedKeyExchange);
    }

    private void initCurve(KeyExchangeAlgorithm kexAlgorithm) {
        switch (kexAlgorithm) {
            case ECDH_SHA2_NISTP256:
                namedGroup = NamedGroup.SECP256R1;
                ellipticCurve = CurveFactory.getCurve(NamedGroup.SECP256R1);
                break;
            case ECDH_SHA2_NISTP384:
                namedGroup = NamedGroup.SECP384R1;
                ellipticCurve = CurveFactory.getCurve(NamedGroup.SECP384R1);
                break;
            case ECDH_SHA2_NISTP521:
                namedGroup = NamedGroup.SECP521R1;
                ellipticCurve = CurveFactory.getCurve(NamedGroup.SECP521R1);
                break;
            default:
                String[] kexParts = kexAlgorithm.name().split("_");
                if (!kexParts[0].equals("ECDH")) {
                    // TODO: Determine, whether throwing and error or continuing with a predetermined curve is better
                    LOGGER.warn("Initializing a new ECDHKeyExchange without an ECDH key exchange algorithm negotiated. Falling back to ecdh-sha2-nistp256.");
                    namedGroup = NamedGroup.SECP256R1;
                } else {
                    namedGroup = NamedGroup.valueOf(kexParts[3]);
                }
                ellipticCurve = CurveFactory.getCurve(namedGroup);
                break;
        }
    }

    public void generateKeyPair() {
        FieldElement ecdhPrivateKey;
        byte[] ecdhPrivateKeyRaw = new byte[ellipticCurve.getBasePointOrder().bitLength()];
        random.nextBytes(ecdhPrivateKeyRaw);
        if (ellipticCurve instanceof EllipticCurveOverFp) {
            ecdhPrivateKey = new FieldElementFp(new BigInteger(1, ecdhPrivateKeyRaw), ellipticCurve.getBasePointOrder());
        } else if (ellipticCurve instanceof EllipticCurveOverF2m) {
            ecdhPrivateKey = new FieldElementF2m(new BigInteger(1, ecdhPrivateKeyRaw),
                    ellipticCurve.getBasePointOrder());
        } else {
            throw new NotImplementedException("ECDHKeyExchange::generateKeyPair");
        }
        Point ecdhPublicKey = ellipticCurve.mult(ecdhPrivateKey.getData(), ellipticCurve.getBasePoint());
        this.localKeyPair = new ECDHKeyPair(namedGroup, ecdhPublicKey, ecdhPrivateKey);
    }

    public void setRemotePublicKey(byte[] serializedPublicKey) {
        Point publicKey = PointFormatter.formatFromByteArray(namedGroup, serializedPublicKey);
        this.remotePublicKey = new ECDHKeyPair(namedGroup, publicKey);
    }

    @Override
    public void computeSharedSecret() {
        Point sharedPoint = ellipticCurve.mult(localKeyPair.getEcdhPrivateKey().getData(),
                remotePublicKey.getEcdhPublicKey());
        sharedSecret = sharedPoint.getFieldX().getData().toByteArray();
        // Strip leading 0 bytes
        while (sharedSecret[0] == 0) {
            sharedSecret = Arrays.copyOfRange(sharedSecret, 1, sharedSecret.length);
        }
        LOGGER.debug("Finished computation of shared secret: " + ArrayConverter.bytesToRawHexString(sharedSecret));
    }

    @Override
    public ECDHKeyPair getLocalKeyPair() {
        return localKeyPair;
    }

    @Override
    public ECDHKeyPair getRemotePublicKey() {
        return remotePublicKey;
    }

    public static class ECDHKeyPair extends KeyPair {
        private final NamedGroup ecdhGroup;
        private final FieldElement ecdhPrivateKey;
        private final Point ecdhPublicKey;

        ECDHKeyPair(NamedGroup namedGroup, Point ecdhPublicKey) {
            this(namedGroup, ecdhPublicKey, null);
        }

        ECDHKeyPair(NamedGroup namedGroup, Point ecdhPublicKey, FieldElement ecdhPrivateKey) {
            this.ecdhGroup = namedGroup;
            this.ecdhPrivateKey = ecdhPrivateKey;
            this.ecdhPublicKey = ecdhPublicKey;
        }

        public NamedGroup getEcdhGroup() {
            return ecdhGroup;
        }

        public Point getEcdhPublicKey() {
            return ecdhPublicKey;
        }

        public FieldElement getEcdhPrivateKey() {
            return ecdhPrivateKey;
        }

        @Override
        public byte[] serializePrivateKey() {
            if (ecdhPrivateKey == null) {
                return new byte[0];
            }
            return ArrayConverter.bigIntegerToByteArray(ecdhPrivateKey.getData());
        }

        @Override
        public byte[] serializePublicKey() {
            return PointFormatter.formatToByteArray(ecdhGroup, ecdhPublicKey, ECPointFormat.UNCOMPRESSED);
        }
    }
}
