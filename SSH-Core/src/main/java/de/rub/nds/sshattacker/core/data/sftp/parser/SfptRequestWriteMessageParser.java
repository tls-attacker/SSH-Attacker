/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestWriteMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SfptRequestWriteMessageParser
        extends SftpRequestWithHandleMessageParser<SfptRequestWriteMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SfptRequestWriteMessageParser(byte[] array) {
        super(array);
    }

    public SfptRequestWriteMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SfptRequestWriteMessage createMessage() {
        return new SfptRequestWriteMessage();
    }

    private void parseOffset() {
        message.setOffset(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("Offset: {}", message.getOffset().getValue());
    }

    private void parseData() {
        message.setDataLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Data length: {}", message.getDataLength().getValue());
        message.setData(parseByteArrayField(message.getDataLength().getValue()));
        LOGGER.debug(
                "Data: {}", () -> ArrayConverter.bytesToRawHexString(message.getData().getValue()));
    }

    @Override
    protected void parseRequestWithHandleSpecificContents() {
        parseOffset();
        parseData();
    }
}
