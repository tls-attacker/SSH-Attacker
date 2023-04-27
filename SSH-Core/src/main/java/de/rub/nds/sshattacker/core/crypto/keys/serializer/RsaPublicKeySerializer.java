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

import java.nio.charset.StandardCharsets;

/** Serializer class to encode an RSA public key to the ssh-rsa format. */
public class RsaPublicKeySerializer extends Serializer<CustomRsaPublicKey> {

    private final CustomRsaPublicKey publicKey;

    public RsaPublicKeySerializer(CustomRsaPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    protected void serializeBytes() {
        /*
         * The ssh-rsa format as specified in RFC4253 Section 6.6:
         *   string    "ssh-rsa"
         *   mpint     e
         *   mpint     n
         */
        appendInt(
                PublicKeyFormat.SSH_RSA.toString().getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(PublicKeyFormat.SSH_RSA.toString(), StandardCharsets.US_ASCII);
        byte[] encodedExponent = publicKey.getPublicExponent().toByteArray();
        appendInt(encodedExponent.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        appendBytes(encodedExponent);
        byte[] encodedModulus = publicKey.getModulus().toByteArray();
        appendInt(encodedModulus.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        appendBytes(encodedModulus);
    }
}
