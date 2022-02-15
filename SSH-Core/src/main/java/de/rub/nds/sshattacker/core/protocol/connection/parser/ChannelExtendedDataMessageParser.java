/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelExtendedDataMessageParser
        extends ChannelMessageParser<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public ChannelExtendedDataMessage createMessage() {
        return new ChannelExtendedDataMessage();
    }

    private void parseDataTypeCode() {
        message.setDataTypeCode(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Data type code: " + message.getDataTypeCode().getValue());
        LOGGER.debug(
                "Data type: "
                        + ExtendedChannelDataType.fromDataTypeCode(
                                message.getDataTypeCode().getValue()));
    }

    private void parseData() {
        message.setDataLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Data length: " + message.getDataLength().getValue());
        message.setData(parseByteArrayField(message.getDataLength().getValue()), false);
        LOGGER.debug("Data: " + ArrayConverter.bytesToRawHexString(message.getData().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseDataTypeCode();
        parseData();
    }
}
