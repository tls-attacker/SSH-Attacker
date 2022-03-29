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
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Parser class to parse an RSA public key in the ssh-rsa format. */
public class RsaPublicKeyParser
        extends Parser<SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey>> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> parse() {
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey();
        // The ssh-rsa format specifies the ssh-rsa to be part of the key
        int formatLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        if (!format.equals(PublicKeyFormat.SSH_RSA.getName())) {
            LOGGER.warn(
                    "Trying to parse RSA public key, but encountered unexpected public key format '"
                            + format
                            + "'. Parsing will continue but may not yield the expected results.");
        }
        int publicExponentLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        publicKey.setPublicExponent(parseBigIntField(publicExponentLength));

        int modulusLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        publicKey.setModulus(parseBigIntField(modulusLength));

        return new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey);
    }
}
