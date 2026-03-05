/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Parser class to parse an DSA public key in the ssh-dss format. */
public class DsaPublicKeyParser
        extends Parser<SshPublicKey<CustomDsaPublicKey, CustomDsaPrivateKey>> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomDsaPublicKey, CustomDsaPrivateKey> parse() {
        CustomDsaPublicKey publicKey = new CustomDsaPublicKey();
        // The ssh-dss format specified the ssh-dss to be part of the encoded key
        int formatLength = parseIntField();
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        if (!format.equals(PublicKeyFormat.SSH_DSS.getName())) {
            LOGGER.warn(
                    "Trying to parse an DSA public key, but encountered unexpected public key format '{}'. Parsing will continue but may not yield the expected results.",
                    format);
        }
        int pLength = parseIntField();
        publicKey.setP(parseBigIntField(pLength));
        int qLength = parseIntField();
        publicKey.setQ(parseBigIntField(qLength));
        int gLength = parseIntField();
        publicKey.setG(parseBigIntField(gLength));
        int yLength = parseIntField();
        publicKey.setY(parseBigIntField(yLength));

        return new SshPublicKey<>(PublicKeyFormat.SSH_DSS, publicKey);
    }
}
