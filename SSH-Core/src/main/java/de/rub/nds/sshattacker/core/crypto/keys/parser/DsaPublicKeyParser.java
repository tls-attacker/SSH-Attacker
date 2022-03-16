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
import de.rub.nds.sshattacker.core.crypto.keys.CustomDsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Parser class to parse an DSA public key in the ssh-dss format. */
public class DsaPublicKeyParser extends Parser<CustomDsaPublicKey> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public CustomDsaPublicKey parse() {
        CustomDsaPublicKey publicKey = new CustomDsaPublicKey();
        // The ssh-dss format specified the ssh-dss to be part of the encoded key
        int formatLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        if (!format.equals(PublicKeyFormat.SSH_DSS.getName())) {
            LOGGER.warn(
                    "Trying to parse an DSA public key, but encountered unexpected public key format '"
                            + format
                            + "'. Parsing will continue but may not yield the expected results.");
        }
        publicKey.setPLength(parseIntField(DataFormatConstants.MPINT_SIZE_LENGTH));
        publicKey.setP(parseBigIntField(publicKey.getPLength().getValue()));
        publicKey.setQLength(parseIntField(DataFormatConstants.MPINT_SIZE_LENGTH));
        publicKey.setQ(parseBigIntField(publicKey.getQLength().getValue()));
        publicKey.setGLength(parseIntField(DataFormatConstants.MPINT_SIZE_LENGTH));
        publicKey.setG(parseBigIntField(publicKey.getGLength().getValue()));
        publicKey.setYLength(parseIntField(DataFormatConstants.MPINT_SIZE_LENGTH));
        publicKey.setY(parseBigIntField(publicKey.getYLength().getValue()));

        return publicKey;
    }
}
