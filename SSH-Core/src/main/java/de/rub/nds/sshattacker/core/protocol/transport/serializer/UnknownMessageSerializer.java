/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageSerializer extends MessageSerializer<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageSerializer(UnknownMessage msg) {
        super(msg);
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(msg.getPayload()));
        appendBytes(msg.getPayload().getValue());
    }
}
