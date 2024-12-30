/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCopyDataMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCopyDataMessageSerializer
        extends SftpRequestExtendedWithHandleMessageSerializer<SftpRequestCopyDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeReadFromOffset(
            SftpRequestCopyDataMessage object, SerializerStream output) {
        Long readFromOffset = object.getReadFromOffset().getValue();
        LOGGER.debug("ReadFromOffset: {}", readFromOffset);
        output.appendLong(readFromOffset);
    }

    private static void serializeReadDataLength(
            SftpRequestCopyDataMessage object, SerializerStream output) {
        Long readDataLength = object.getReadDataLength().getValue();
        LOGGER.debug("ReadDataLength: {}", readDataLength);
        output.appendLong(readDataLength);
    }

    private static void serializeWriteToHandle(
            SftpRequestCopyDataMessage object, SerializerStream output) {
        Integer writeToHandleLength = object.getWriteToHandleLength().getValue();
        LOGGER.debug("WriteToHandle length: {}", writeToHandleLength);
        output.appendInt(writeToHandleLength);
        byte[] writeToHandle = object.getWriteToHandle().getValue();
        LOGGER.debug("WriteToHandle: {}", () -> ArrayConverter.bytesToRawHexString(writeToHandle));
        output.appendBytes(writeToHandle);
    }

    private static void serializeWriteToOffset(
            SftpRequestCopyDataMessage object, SerializerStream output) {
        Long writeToOffset = object.getWriteToOffset().getValue();
        LOGGER.debug("WriteToOffset: {}", writeToOffset);
        output.appendLong(writeToOffset);
    }

    @Override
    protected void serializeRequestExtendedWithHandleSpecificContents(
            SftpRequestCopyDataMessage object, SerializerStream output) {
        serializeReadFromOffset(object, output);
        serializeReadDataLength(object, output);
        serializeWriteToHandle(object, output);
        serializeWriteToOffset(object, output);
    }
}
