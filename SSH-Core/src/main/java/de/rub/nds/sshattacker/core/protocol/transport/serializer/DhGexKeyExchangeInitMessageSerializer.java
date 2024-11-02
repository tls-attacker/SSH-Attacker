/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeInitMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeInitMessageSerializer(DhGexKeyExchangeInitMessage message) {
        super(message);
    }

    private void serializeEphemeralPublicKey() {
        Integer ephemeralPublicKeyLength = message.getEphemeralPublicKeyLength().getValue();
        LOGGER.debug("Ephemeral public key (client) length: {}", ephemeralPublicKeyLength);
        appendInt(ephemeralPublicKeyLength, DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug(
                "Ephemeral public key (client): {}", message.getEphemeralPublicKey().getValue());
        appendBytes(message.getEphemeralPublicKey().getValue().toByteArray());
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeEphemeralPublicKey();
    }
}
