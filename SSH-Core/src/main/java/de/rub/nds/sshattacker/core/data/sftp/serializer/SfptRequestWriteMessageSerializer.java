/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestWriteMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SfptRequestWriteMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SfptRequestWriteMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SfptRequestWriteMessageSerializer(SfptRequestWriteMessage message) {
        super(message);
    }

    private void serializeOffset() {
        LOGGER.debug("Offset: {}", message.getOffset().getValue());
        appendLong(message.getOffset().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    public void serializeData() {
        LOGGER.debug("Data length: {}", message.getDataLength().getValue());
        appendInt(message.getDataLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Data: {}", () -> ArrayConverter.bytesToRawHexString(message.getData().getValue()));
        appendBytes(message.getData().getValue());
    }

    @Override
    protected void serializeRequestWithHandleSpecificContents() {
        serializeOffset();
        serializeData();
    }
}
