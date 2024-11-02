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
        LOGGER.debug("ReadFromOffset: {}", message.getReadFromOffset().getValue());
        appendLong(message.getReadFromOffset().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    private void serializeReadDataLength() {
        LOGGER.debug("ReadDataLength: {}", message.getReadDataLength().getValue());
        appendLong(message.getReadDataLength().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    private void serializeWriteToHandle() {
        LOGGER.debug("WriteToHandle length: {}", message.getWriteToHandleLength().getValue());
        appendInt(
                message.getWriteToHandleLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "WriteToHandle: {}",
                () -> ArrayConverter.bytesToRawHexString(message.getWriteToHandle().getValue()));
        appendBytes(message.getWriteToHandle().getValue());
    }

    private void serializeWriteToOffset() {
        LOGGER.debug("WriteToOffset: {}", message.getWriteToOffset().getValue());
        appendLong(message.getWriteToOffset().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    @Override
    protected void serializeRequestExtendedWithHandleSpecificContents() {
        serializeReadFromOffset();
        serializeReadDataLength();
        serializeWriteToHandle();
        serializeWriteToOffset();
    }
}
