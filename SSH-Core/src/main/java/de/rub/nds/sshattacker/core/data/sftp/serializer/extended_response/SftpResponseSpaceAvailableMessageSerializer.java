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
        Long bytesOnDevice = message.getBytesOnDevice().getValue();
        LOGGER.debug("BytesOnDevice: {}", bytesOnDevice);
        appendLong(bytesOnDevice, DataFormatConstants.UINT64_SIZE);

        Long unusedBytesOnDevice = message.getUnusedBytesOnDevice().getValue();
        LOGGER.debug("UnusedBytesOnDevice: {}", unusedBytesOnDevice);
        appendLong(unusedBytesOnDevice, DataFormatConstants.UINT64_SIZE);

        Long bytesAvailableToUser = message.getBytesAvailableToUser().getValue();
        LOGGER.debug("BytesAvailableToUser: {}", bytesAvailableToUser);
        appendLong(bytesAvailableToUser, DataFormatConstants.UINT64_SIZE);

        Long unusedBytesAvailableToUser = message.getUnusedBytesAvailableToUser().getValue();
        LOGGER.debug("UnusedBytesAvailableToUser: {}", unusedBytesAvailableToUser);
        appendLong(unusedBytesAvailableToUser, DataFormatConstants.UINT64_SIZE);

        Integer bytesPerAllocationUnit = message.getBytesPerAllocationUnit().getValue();
        LOGGER.debug("BytesPerAllocationUnit: {}", bytesPerAllocationUnit);
        appendInt(bytesPerAllocationUnit, DataFormatConstants.UINT32_SIZE);
    }
}
