/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.response.SftpResponseMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseSpaceAvailableMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseSpaceAvailableMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseSpaceAvailableMessage object, SerializerStream output) {
        Long bytesOnDevice = object.getBytesOnDevice().getValue();
        LOGGER.debug("BytesOnDevice: {}", bytesOnDevice);
        output.appendLong(bytesOnDevice);

        Long unusedBytesOnDevice = object.getUnusedBytesOnDevice().getValue();
        LOGGER.debug("UnusedBytesOnDevice: {}", unusedBytesOnDevice);
        output.appendLong(unusedBytesOnDevice);

        Long bytesAvailableToUser = object.getBytesAvailableToUser().getValue();
        LOGGER.debug("BytesAvailableToUser: {}", bytesAvailableToUser);
        output.appendLong(bytesAvailableToUser);

        Long unusedBytesAvailableToUser = object.getUnusedBytesAvailableToUser().getValue();
        LOGGER.debug("UnusedBytesAvailableToUser: {}", unusedBytesAvailableToUser);
        output.appendLong(unusedBytesAvailableToUser);

        Integer bytesPerAllocationUnit = object.getBytesPerAllocationUnit().getValue();
        LOGGER.debug("BytesPerAllocationUnit: {}", bytesPerAllocationUnit);
        output.appendInt(bytesPerAllocationUnit);
    }
}
