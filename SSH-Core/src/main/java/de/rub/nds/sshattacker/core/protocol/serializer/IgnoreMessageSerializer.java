/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.message.IgnoreMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IgnoreMessageSerializer extends MessageSerializer<IgnoreMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public IgnoreMessageSerializer(IgnoreMessage msg) {
        super(msg);
    }

    private void serializeDataLength() {
        LOGGER.debug("Data length: " + msg.getData().getValue().length);
        appendInt(msg.getData().getValue().length, BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializeData() {
        LOGGER.debug("Data: " + ArrayConverter.bytesToRawHexString(msg.getData().getValue()));
        appendBytes(msg.getData().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeDataLength();
        serializeData();
        return getAlreadySerialized();
    }

}
