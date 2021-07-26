/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelExtendedDataMessageParser extends ChannelMessageParser<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public ChannelExtendedDataMessage createMessage() {
        return new ChannelExtendedDataMessage();
    }

    private void parseDataTypeCode(ChannelExtendedDataMessage msg) {
        msg.setDataTypeCode(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Data type code: " + msg.getDataTypeCode().getValue());
        LOGGER.debug("Data type: " + ExtendedChannelDataType.fromDataTypeCode(msg.getDataTypeCode().getValue()));
    }

    private void parseData(ChannelExtendedDataMessage msg) {
        msg.setDataLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Data length: " + msg.getDataLength().getValue());
        msg.setData(parseByteArrayField(msg.getDataLength().getValue()));
        LOGGER.debug("Data: " + ArrayConverter.bytesToRawHexString(msg.getData().getValue()));
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelExtendedDataMessage msg) {
        super.parseMessageSpecificPayload(msg);
        parseDataTypeCode(msg);
        parseData(msg);
    }

}
