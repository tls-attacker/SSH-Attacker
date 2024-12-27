/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;

public class XCurveEcPublicKeySerializer extends Serializer<XCurveEcPublicKey> {

    @Override
    protected void serializeBytes(XCurveEcPublicKey object, SerializerStream output) {
        /*
         * The ssh-ed25519 / ed448 format as specified in RFC 8709 Section 4:
         *   string    "ssh-[ed25519|ed448]"
         *   string    key
         */
        PublicKeyFormat format;
        if (object.getGroup() == NamedEcGroup.CURVE25519) {
            format = PublicKeyFormat.SSH_ED25519;
        } else {
            format = PublicKeyFormat.SSH_ED448;
        }
        output.appendInt(
                format.getName().getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendString(format.getName(), StandardCharsets.US_ASCII);
        output.appendInt(object.getCoordinate().length, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(object.getCoordinate());
    }
}
