/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IgnoreMessageSerializer extends SshMessageSerializer<IgnoreMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public IgnoreMessageSerializer(IgnoreMessage message) {
        super(message);
    }

    private void serializeData() {
        LOGGER.debug("Data length: {}", message.getDataLength().getValue());
        appendInt(message.getDataLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Data: {}", ArrayConverter.bytesToRawHexString(message.getData().getValue()));
        appendBytes(message.getData().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeData();
    }
}
