/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.PongMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PongMessageParser extends SshMessageParser<PongMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PongMessageParser(byte[] array) {
        super(array);
    }

    public PongMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected PongMessage createMessage() {
        return new PongMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        int dataLength = parseIntField();
        message.setDataLength(dataLength);
        LOGGER.debug("Data length: {}", dataLength);
        byte[] data = parseByteArrayField(dataLength);
        message.setData(data);
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
    }
}
