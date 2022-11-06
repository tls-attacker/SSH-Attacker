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
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup761X25519KeyExchange extends HybridKeyExchange {
    private static final Logger LOGGER = LogManager.getLogger();

    public Sntrup761X25519KeyExchange() {
        super();
        agreement.put("ec25519", new XCurveEcdhKeyExchange(NamedEcGroup.CURVE25519));
        encapsulation.put("sntrup761", new Sntrup761KeyExchange());
    }

    public byte[] getPublicKeys() {
        return mergeKeyExchanges(
                encapsulation.get("sntrup761").getLocalKeyPair().getPublic().getEncoded(),
                agreement.get("ec25519").getLocalKeyPair().getPublic().getEncoded());
    }

    private byte[] mergeKeyExchanges(byte[] sntrup, byte[] ec25519) {
        byte[] mergedKeys = new byte[sntrup.length + ec25519.length];
        ByteBuffer buff = ByteBuffer.wrap(mergedKeys);
        buff.put(sntrup);
        buff.put(ec25519);
        return buff.array();
    }

    @Override
    public void combineSharedSecrets() {
        try {
            agreement.get("ec25519").computeSharedSecret();
            if (encapsulation.get("sntrup761").getSharedSecret() == null) {
                encapsulation.get("sntrup761").decryptSharedSecret();
            }

            byte[] tmpSharedSecret =
                    mergeKeyExchanges(
                            ArrayConverter.bigIntegerToByteArray(
                                    encapsulation.get("sntrup761").getSharedSecret()),
                            ArrayConverter.bigIntegerToByteArray(
                                    agreement.get("ec25519").getSharedSecret()));
            this.sharedSecret = new BigInteger(encode(tmpSharedSecret));
            LOGGER.debug(
                    "Concatenated Shared Secret: "
                            + ArrayConverter.bytesToRawHexString(tmpSharedSecret));
            LOGGER.debug(
                    "Encoded Shared Secret: "
                            + ArrayConverter.bytesToRawHexString(encode(tmpSharedSecret)));
        } catch (Exception e) {
            LOGGER.warn("Could not create the shared Secret: " + e);
        }
    }

    private byte[] encode(byte[] sharedSecret) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            return md.digest(sharedSecret);

        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Could not get MessageDigest: " + e);
        }
        return new byte[0];
    }
}
