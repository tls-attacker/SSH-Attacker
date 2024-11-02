/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestWriteMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestWriteMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SftpRequestWriteMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestWriteMessageSerializer(SftpRequestWriteMessage message) {
        super(message);
    }

    private void serializeOffset() {
        Long offset = message.getOffset().getValue();
        LOGGER.debug("Offset: {}", offset);
        appendLong(offset, DataFormatConstants.UINT64_SIZE);
    }

    private void serializeData() {
        Integer dataLength = message.getDataLength().getValue();
        LOGGER.debug("Data length: {}", dataLength);
        appendInt(dataLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] data = message.getData().getValue();
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
        appendBytes(data);
    }

    @Override
    protected void serializeRequestWithHandleSpecificContents() {
        serializeOffset();
        serializeData();
    }
}
