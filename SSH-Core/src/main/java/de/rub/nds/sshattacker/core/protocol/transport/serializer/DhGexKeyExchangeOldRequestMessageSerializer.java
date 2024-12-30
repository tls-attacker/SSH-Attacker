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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeOldRequestMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeOldRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializePreferredGroupSize(
            DhGexKeyExchangeOldRequestMessage object, SerializerStream output) {
        Integer preferredGroupSize = object.getPreferredGroupSize().getValue();
        LOGGER.debug("Preferred group size: {}", preferredGroupSize);
        output.appendInt(preferredGroupSize);
    }

    @Override
    protected void serializeMessageSpecificContents(
            DhGexKeyExchangeOldRequestMessage object, SerializerStream output) {
        serializePreferredGroupSize(object, output);
    }
}
