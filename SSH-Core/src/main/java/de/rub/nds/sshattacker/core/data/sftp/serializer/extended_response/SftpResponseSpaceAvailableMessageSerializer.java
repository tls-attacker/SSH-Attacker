/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseSpaceAvailableMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseSpaceAvailableMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseSpaceAvailableMessageSerializer(SftpResponseSpaceAvailableMessage message) {
        super(message);
    }

    @Override
    protected void serializeResponseSpecificContents() {
        LOGGER.debug("BytesOnDevice: {}", message.getBytesOnDevice().getValue());
        appendLong(message.getBytesOnDevice().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("UnusedBytesOnDevice: {}", message.getUnusedBytesOnDevice().getValue());
        appendLong(message.getUnusedBytesOnDevice().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("BytesAvailableToUser: {}", message.getBytesAvailableToUser().getValue());
        appendLong(message.getBytesAvailableToUser().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug(
                "UnusedBytesAvailableToUser: {}",
                message.getUnusedBytesAvailableToUser().getValue());
        appendLong(
                message.getUnusedBytesAvailableToUser().getValue(),
                DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("BytesPerAllocationUnit: {}", message.getBytesPerAllocationUnit().getValue());
        appendInt(message.getBytesPerAllocationUnit().getValue(), DataFormatConstants.UINT32_SIZE);
    }
}
