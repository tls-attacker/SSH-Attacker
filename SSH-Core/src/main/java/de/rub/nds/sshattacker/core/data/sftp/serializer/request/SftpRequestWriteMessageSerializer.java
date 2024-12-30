/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestWriteMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestWriteMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SftpRequestWriteMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeOffset(SftpRequestWriteMessage object, SerializerStream output) {
        Long offset = object.getOffset().getValue();
        LOGGER.debug("Offset: {}", offset);
        output.appendLong(offset);
    }

    private static void serializeData(SftpRequestWriteMessage object, SerializerStream output) {
        Integer dataLength = object.getDataLength().getValue();
        LOGGER.debug("Data length: {}", dataLength);
        output.appendInt(dataLength);
        byte[] data = object.getData().getValue();
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
        output.appendBytes(data);
    }

    @Override
    protected void serializeRequestWithHandleSpecificContents(
            SftpRequestWriteMessage object, SerializerStream output) {
        serializeOffset(object, output);
        serializeData(object, output);
    }
}
