/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelExtendedDataMessageParser
        extends ChannelMessageParser<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessageParser(byte[] array) {
        super(array);
    }

    public ChannelExtendedDataMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public ChannelExtendedDataMessage createMessage() {
        return new ChannelExtendedDataMessage();
    }

    private void parseDataTypeCode() {
        int dataTypeCode = parseIntField();
        message.setDataTypeCode(dataTypeCode);
        LOGGER.debug("Data type code: {}", dataTypeCode);
        LOGGER.debug(
                "Data type: {}",
                ExtendedChannelDataType.fromDataTypeCode(message.getDataTypeCode().getValue()));
    }

    private void parseData() {
        int dataLength = parseIntField();
        message.setDataLength(dataLength);
        LOGGER.debug("Data length: {}", dataLength);
        byte[] data = parseByteArrayField(dataLength);
        message.setData(data);
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseDataTypeCode();
        parseData();
    }
}
