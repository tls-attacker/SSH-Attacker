/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Parser class to parse an RSA public key in the ssh-rsa format. */
public class RsaPublicKeyParser extends Parser<CustomRsaPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public CustomRsaPublicKey parse() {
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey();
        // The ssh-rsa format specifies the ssh-rsa to be part of the key
        int formatLength = parseIntField(DataFormatConstants.INT32_SIZE);
        String format = parseByteString(formatLength);
        if (!format.equals(PublicKeyFormat.SSH_RSA.getName())) {
            LOGGER.warn(
                    "Trying to parse RSA public key, but encountered unexpected public key format '"
                            + format
                            + "'. Parsing will continue but may not yield the expected results.");
        }
        publicKey.setPublicExponentLength(parseIntField(DataFormatConstants.INT32_SIZE));
        publicKey.setPublicExponent(
                parseBigIntField(publicKey.getPublicExponentLength().getValue()));

        publicKey.setModulusLength(parseIntField(DataFormatConstants.INT32_SIZE));
        // Length should be adjusted, in case the modulus starts with 00 byte(s)
        publicKey.setModulus(parseBigIntField(publicKey.getModulusLength().getValue()), true);

        return publicKey;
    }
}
