/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageSerializer extends SshMessageSerializer<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageSerializer(UnknownMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {
        LOGGER.debug("Payload: {}", ArrayConverter.bytesToHexString(message.getPayload()));
        appendBytes(message.getPayload().getValue());
    }
}
