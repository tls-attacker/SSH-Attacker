/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class XCurvePublicKeyParser
        extends Parser<SshPublicKey<XCurveEcPublicKey, XCurveEcPrivateKey>> {

    private static final Logger LOGGER = LogManager.getLogger();

    public XCurvePublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<XCurveEcPublicKey, XCurveEcPrivateKey> parse() {
        int formatLength = parseIntField(DataFormatConstants.INT32_SIZE);
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        NamedGroup group;
        if (format.equals(PublicKeyFormat.SSH_ED25519.getName())) {
            group = NamedGroup.CURVE25519;
        } else if (format.equals(PublicKeyFormat.SSH_ED448.getName())) {
            group = NamedGroup.CURVE448;
        } else {
            LOGGER.warn(
                    "Trying to parse X curve public key, but encountered unexpected public key format '"
                            + format
                            + "'. Parsing will continue as Curve22519 but may not yield the expected results.");
            group = NamedGroup.CURVE25519;
        }

        int publicKeyLength = parseIntField(DataFormatConstants.INT32_SIZE);
        byte[] publicKeyBytes = parseByteArrayField(publicKeyLength);
        XCurveEcPublicKey publicKey = new XCurveEcPublicKey(publicKeyBytes, group);

        return new SshPublicKey<>(PublicKeyFormat.fromName(format), publicKey);
    }
}
