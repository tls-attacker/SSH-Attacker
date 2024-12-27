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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;

/** Serializer class to encode an ECDSA public key to the ecdsa-sha2-* format */
public class EcPublicKeySerializer extends Serializer<CustomEcPublicKey> {

    @Override
    protected void serializeBytes(CustomEcPublicKey object, SerializerStream output) {
        /*
         * The ecdsa-sha2-* format as specified in RFC5656 Section 3.1:
         *   string    "ecdsa-sha2-[identifier]"
         *   string    [identifier]
         *   string    Q
         */
        output.appendInt(
                11 + object.getGroup().getIdentifier().getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendString("ecdsa-sha2-", StandardCharsets.US_ASCII);
        output.appendString(object.getGroup().getIdentifier(), StandardCharsets.US_ASCII);
        output.appendInt(
                object.getGroup().getIdentifier().getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendString(object.getGroup().getIdentifier(), StandardCharsets.US_ASCII);
        byte[] encodedQ =
                PointFormatter.formatToByteArray(
                        object.getGroup(), object.getWAsPoint(), EcPointFormat.UNCOMPRESSED);
        output.appendInt(encodedQ.length, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(encodedQ);
    }
}
