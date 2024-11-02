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
        message.setReadFromOffset(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("ReadFromOffset: {}", message.getReadFromOffset().getValue());
    }

    private void parseReadDataLength() {
        message.setReadDataLength(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("ReadDataLength: {}", message.getReadDataLength().getValue());
    }

    private void parseWriteToHandle() {
        message.setWriteToHandleLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("WriteToHandle length: {}", message.getWriteToHandleLength().getValue());
        message.setWriteToHandle(parseByteArrayField(message.getWriteToHandleLength().getValue()));
        LOGGER.debug(
                "WriteToHandle: {}",
                () -> ArrayConverter.bytesToRawHexString(message.getWriteToHandle().getValue()));
    }

    private void parseWriteToOffset() {
        message.setWriteToOffset(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("WriteToOffset: {}", message.getWriteToOffset().getValue());
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
