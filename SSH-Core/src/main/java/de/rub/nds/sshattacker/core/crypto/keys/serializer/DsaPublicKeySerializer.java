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
import de.rub.nds.sshattacker.core.crypto.keys.CustomDsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;

import java.nio.charset.StandardCharsets;

/** Serializer class to encode an DSA public key to the ssh-dsa format. */
public class DsaPublicKeySerializer extends Serializer<CustomDsaPublicKey> {

    private final CustomDsaPublicKey publicKey;

    public DsaPublicKeySerializer(CustomDsaPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    protected void serializeBytes() {
        /*
         * The ssh-dss format as specified in RFC4253 Section 6.6:
         *   string    "ssh-dss"
         *   mpint     p
         *   mpint     q
         *   mpint     g
         *   mpint     y
         */
        appendInt(
                PublicKeyFormat.SSH_DSS.getName().getBytes(StandardCharsets.US_ASCII).length,
                DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(PublicKeyFormat.SSH_DSS.getName(), StandardCharsets.US_ASCII);
        byte[] encodedP = publicKey.getParams().getP().toByteArray();
        appendInt(encodedP.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        appendBytes(encodedP);
        byte[] encodedQ = publicKey.getParams().getQ().toByteArray();
        appendInt(encodedQ.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        appendBytes(encodedQ);
        byte[] encodedG = publicKey.getParams().getG().toByteArray();
        appendInt(encodedG.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        appendBytes(encodedG);
        byte[] encodedY = publicKey.getY().toByteArray();
        appendInt(encodedY.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        appendBytes(encodedY);
    }
}
