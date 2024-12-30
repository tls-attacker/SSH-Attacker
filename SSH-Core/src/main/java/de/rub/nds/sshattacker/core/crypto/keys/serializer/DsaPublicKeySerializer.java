/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;

/** Serializer class to encode an DSA public key to the ssh-dsa format. */
public class DsaPublicKeySerializer extends Serializer<CustomDsaPublicKey> {

    @Override
    protected void serializeBytes(CustomDsaPublicKey object, SerializerStream output) {
        /*
         * The ssh-dss format as specified in RFC4253 Section 6.6:
         *   string    "ssh-dss"
         *   mpint     p
         *   mpint     q
         *   mpint     g
         *   mpint     y
         */
        output.appendLengthPrefixedString(
                PublicKeyFormat.SSH_DSS.getName(), StandardCharsets.US_ASCII);
        output.appendLengthPrefixedBigInteger(object.getParams().getP());
        output.appendLengthPrefixedBigInteger(object.getParams().getQ());
        output.appendLengthPrefixedBigInteger(object.getParams().getG());
        output.appendLengthPrefixedBigInteger(object.getY());
    }
}
