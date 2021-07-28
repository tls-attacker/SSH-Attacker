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
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IgnoreMessageSerializer extends MessageSerializer<IgnoreMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public IgnoreMessageSerializer(IgnoreMessage msg) {
        super(msg);
    }

    private void serializeData() {
        LOGGER.debug("Data length: " + msg.getDataLength().getValue());
        appendInt(msg.getDataLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Data: " + ArrayConverter.bytesToRawHexString(msg.getData().getValue()));
        appendBytes(msg.getData().getValue());
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        serializeData();
    }
}
