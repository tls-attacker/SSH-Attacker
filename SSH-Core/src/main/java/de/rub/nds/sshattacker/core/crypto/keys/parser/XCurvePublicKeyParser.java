/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class XCurvePublicKeyParser
        extends Parser<SshPublicKey<XCurveEcPublicKey, XCurveEcPrivateKey>> {

    private static final Logger LOGGER = LogManager.getLogger();

    public XCurvePublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<XCurveEcPublicKey, XCurveEcPrivateKey> parse() {
        int formatLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        String format = parseByteString(formatLength, StandardCharsets.US_ASCII);
        NamedEcGroup group;
        if (format.equals(PublicKeyFormat.SSH_ED25519.getName())) {
            group = NamedEcGroup.CURVE25519;
        } else if (format.equals(PublicKeyFormat.SSH_ED448.getName())) {
            group = NamedEcGroup.CURVE448;
        } else {
            LOGGER.warn(
                    "Trying to parse X curve public key, but encountered unexpected public key format '"
                            + format
                            + "'. Parsing will continue as Curve22519 but may not yield the expected results.");
            group = NamedEcGroup.CURVE25519;
        }

        int publicKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        byte[] publicKeyBytes = parseByteArrayField(publicKeyLength);
        XCurveEcPublicKey publicKey = new XCurveEcPublicKey(publicKeyBytes, group);

        return new SshPublicKey<>(PublicKeyFormat.fromName(format), publicKey);
    }
}
