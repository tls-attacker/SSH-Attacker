/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCopyDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCopyDataMessageSerializer
        extends SftpRequestExtendedWithHandleMessageSerializer<SftpRequestCopyDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestCopyDataMessageSerializer(SftpRequestCopyDataMessage message) {
        super(message);
    }

    private void serializeReadFromOffset() {
        Long readFromOffset = message.getReadFromOffset().getValue();
        LOGGER.debug("ReadFromOffset: {}", readFromOffset);
        appendLong(readFromOffset, DataFormatConstants.UINT64_SIZE);
    }

    private void serializeReadDataLength() {
        Long readDataLength = message.getReadDataLength().getValue();
        LOGGER.debug("ReadDataLength: {}", readDataLength);
        appendLong(readDataLength, DataFormatConstants.UINT64_SIZE);
    }

    private void serializeWriteToHandle() {
        Integer writeToHandleLength = message.getWriteToHandleLength().getValue();
        LOGGER.debug("WriteToHandle length: {}", writeToHandleLength);
        appendInt(writeToHandleLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] writeToHandle = message.getWriteToHandle().getValue();
        LOGGER.debug("WriteToHandle: {}", () -> ArrayConverter.bytesToRawHexString(writeToHandle));
        appendBytes(writeToHandle);
    }

    private void serializeWriteToOffset() {
        Long writeToOffset = message.getWriteToOffset().getValue();
        LOGGER.debug("WriteToOffset: {}", writeToOffset);
        appendLong(writeToOffset, DataFormatConstants.UINT64_SIZE);
    }

    @Override
    protected void serializeRequestExtendedWithHandleSpecificContents() {
        serializeReadFromOffset();
        serializeReadDataLength();
        serializeWriteToHandle();
        serializeWriteToOffset();
    }
}
