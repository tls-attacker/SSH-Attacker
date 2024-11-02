/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestWriteMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestWriteMessageParser
        extends SftpRequestWithHandleMessageParser<SftpRequestWriteMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestWriteMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestWriteMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestWriteMessage createMessage() {
        return new SftpRequestWriteMessage();
    }

    private void parseOffset() {
        long offset = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setOffset(offset);
        LOGGER.debug("Offset: {}", offset);
    }

    private void parseData() {
        int dataLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setDataLength(dataLength);
        LOGGER.debug("Data length: {}", dataLength);
        byte[] data = parseByteArrayField(dataLength);
        message.setData(data);
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
    }

    @Override
    protected void parseRequestWithHandleSpecificContents() {
        parseOffset();
        parseData();
    }
}
