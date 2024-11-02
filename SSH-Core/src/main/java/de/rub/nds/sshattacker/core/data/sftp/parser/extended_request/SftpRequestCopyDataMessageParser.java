/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCopyDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCopyDataMessageParser
        extends SftpRequestExtendedWithHandleMessageParser<SftpRequestCopyDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestCopyDataMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestCopyDataMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseReadFromOffset() {
        long readFromOffset = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setReadFromOffset(readFromOffset);
        LOGGER.debug("ReadFromOffset: {}", readFromOffset);
    }

    private void parseReadDataLength() {
        long readDataLength = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setReadDataLength(readDataLength);
        LOGGER.debug("ReadDataLength: {}", readDataLength);
    }

    private void parseWriteToHandle() {
        int writeToHandleLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setWriteToHandleLength(writeToHandleLength);
        LOGGER.debug("WriteToHandle length: {}", writeToHandleLength);
        byte[] writeToHandle = parseByteArrayField(writeToHandleLength);
        message.setWriteToHandle(writeToHandle);
        LOGGER.debug("WriteToHandle: {}", () -> ArrayConverter.bytesToRawHexString(writeToHandle));
    }

    private void parseWriteToOffset() {
        long writeToOffset = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setWriteToOffset(writeToOffset);
        LOGGER.debug("WriteToOffset: {}", writeToOffset);
    }

    @Override
    protected SftpRequestCopyDataMessage createMessage() {
        return new SftpRequestCopyDataMessage();
    }

    @Override
    protected void parseRequestExtendedWithHandleSpecificContents() {
        parseReadFromOffset();
        parseReadDataLength();
        parseWriteToHandle();
        parseWriteToOffset();
    }
}
