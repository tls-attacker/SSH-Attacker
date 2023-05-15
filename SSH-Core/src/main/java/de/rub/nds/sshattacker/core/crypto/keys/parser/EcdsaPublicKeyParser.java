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
import de.rub.nds.sshattacker.core.crypto.ec.Point;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Parser;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

/** Parser class to parse an ECDSA public key in the ecdsa-sha2-* format. */
public class EcdsaPublicKeyParser
        extends Parser<SshPublicKey<CustomEcPublicKey, CustomEcPrivateKey>> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdsaPublicKeyParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SshPublicKey<CustomEcPublicKey, CustomEcPrivateKey> parse() {
        int formatNameLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        String formatName = parseByteString(formatNameLength, StandardCharsets.US_ASCII);
        if (!formatName.startsWith("ecdsa-sha2-")) {
            LOGGER.warn(
                    "Trying to parse ECDSA public key, but encountered unexpected public key format '{}'. Parsing will continue but may not yield the expected results.",
                    formatName);
        }

        int curveIdentifierLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        String curveIdentifier = parseByteString(curveIdentifierLength, StandardCharsets.US_ASCII);
        NamedEcGroup group = NamedEcGroup.fromIdentifier(curveIdentifier);
        assert group != null;

        int publicKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        Point publicKeyPoint =
                PointFormatter.formatFromByteArray(group, parseByteArrayField(publicKeyLength));
        CustomEcPublicKey publicKey = new CustomEcPublicKey(publicKeyPoint, group);

        return new SshPublicKey<>(PublicKeyFormat.fromName(formatName), publicKey);
    }
}
