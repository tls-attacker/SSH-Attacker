/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeInitMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeEphemeralPublicKey(
            DhGexKeyExchangeInitMessage object, SerializerStream output) {
        Integer ephemeralPublicKeyLength = object.getEphemeralPublicKeyLength().getValue();
        LOGGER.debug("Ephemeral public key (client) length: {}", ephemeralPublicKeyLength);
        output.appendInt(ephemeralPublicKeyLength);
        BigInteger ephemeralPublicKey = object.getEphemeralPublicKey().getValue();
        LOGGER.debug("Ephemeral public key (client): {}", ephemeralPublicKey);
        output.appendBytes(ephemeralPublicKey.toByteArray());
    }

    @Override
    protected void serializeMessageSpecificContents(
            DhGexKeyExchangeInitMessage object, SerializerStream output) {
        serializeEphemeralPublicKey(object, output);
    }
}
