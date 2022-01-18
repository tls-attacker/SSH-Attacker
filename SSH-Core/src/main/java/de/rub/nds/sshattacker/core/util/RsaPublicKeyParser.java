/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.util;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.crypto.keys.RsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Parser class to parse an RSA public key in ssh-rsa format (see RFC4253 Section 6.6) */
public class RsaPublicKeyParser extends Parser<RsaPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public RsaPublicKey parse() {
        RsaPublicKey publicKey = new RsaPublicKey();
        int keytypeLength = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        String keytype = parseByteString(keytypeLength);

        if (!keytype.equals("ssh-rsa")) {
            LOGGER.debug("Tried to parse key as rsa key, but type was: " + keytype);
        } else {
            publicKey.setExponentLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
            LOGGER.debug("Exponent length: " + publicKey.getExponentLength().getValue());
            publicKey.setExponent(parseBigIntField(publicKey.getExponentLength().getValue()));
            LOGGER.debug("Exponent: " + publicKey.getExponent().getValue());

            publicKey.setModulusLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
            LOGGER.debug("Modulus length: " + publicKey.getModulusLength().getValue());
            // Length should be adjusted, in case the modulus starts with 00 byte(s)
            publicKey.setModulus(parseBigIntField(publicKey.getModulusLength().getValue()), true);
            LOGGER.debug("Modulus: " + publicKey.getModifiableModulus().getValue());
            return publicKey;
        }

        return null;
    }
}
