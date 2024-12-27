/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;

/** Serializer class to encode an RSA public key to the ssh-rsa format. */
public class RsaPublicKeySerializer extends Serializer<CustomRsaPublicKey> {

    @Override
    protected void serializeBytes(CustomRsaPublicKey object, SerializerStream output) {
        /*
         * The ssh-rsa format as specified in RFC4253 Section 6.6:
         *   string    "ssh-rsa"
         *   mpint     e
         *   mpint     n
         */
        output.appendInt(
                PublicKeyFormat.SSH_RSA.toString().getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendString(PublicKeyFormat.SSH_RSA.toString(), StandardCharsets.US_ASCII);
        byte[] encodedExponent = object.getPublicExponent().toByteArray();
        output.appendInt(encodedExponent.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        output.appendBytes(encodedExponent);
        byte[] encodedModulus = object.getModulus().toByteArray();
        output.appendInt(encodedModulus.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        output.appendBytes(encodedModulus);
    }
}
