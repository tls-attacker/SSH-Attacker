/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.EcPointFormat;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.nio.charset.StandardCharsets;

/** Serializer class to encode an ECDSA public key to the ecdsa-sha2-* format */
public class EcdsaPublicKeySerializer extends Serializer<CustomEcPublicKey> {

    private final CustomEcPublicKey publicKey;

    public EcdsaPublicKeySerializer(CustomEcPublicKey publicKey) {
        super();
        this.publicKey = publicKey;
    }

    @Override
    protected void serializeBytes() {
        /*
         * The ecdsa-sha2-* format as specified in RFC5656 Section 3.1:
         *   string    "ecdsa-sha2-[identifier]"
         *   string    [identifier]
         *   string    Q
         */
        appendInt(
                11
                        + publicKey
                                .getGroup()
                                .getIdentifier()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        appendString("ecdsa-sha2-", StandardCharsets.US_ASCII);
        appendString(publicKey.getGroup().getIdentifier(), StandardCharsets.US_ASCII);
        appendInt(
                publicKey.getGroup().getIdentifier().getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(publicKey.getGroup().getIdentifier(), StandardCharsets.US_ASCII);
        byte[] encodedQ =
                PointFormatter.formatToByteArray(
                        publicKey.getGroup(), publicKey.getWAsPoint(), EcPointFormat.UNCOMPRESSED);
        appendInt(encodedQ.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(encodedQ);
    }
}
