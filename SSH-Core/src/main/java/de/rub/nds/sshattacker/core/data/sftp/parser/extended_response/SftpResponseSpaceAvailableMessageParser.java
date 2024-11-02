/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseSpaceAvailableMessageParser
        extends SftpResponseMessageParser<SftpResponseSpaceAvailableMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseSpaceAvailableMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseSpaceAvailableMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseSpaceAvailableMessage createMessage() {
        return new SftpResponseSpaceAvailableMessage();
    }

    @Override
    protected void parseResponseSpecificContents() {
        long bytesOnDevice = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setBytesOnDevice(bytesOnDevice);
        LOGGER.debug("BytesOnDevice: {}", bytesOnDevice);

        long unusedBytesOnDevice = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setUnusedBytesOnDevice(unusedBytesOnDevice);
        LOGGER.debug("UnusedBytesOnDevice: {}", unusedBytesOnDevice);

        long bytesAvailableToUser = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setBytesAvailableToUser(bytesAvailableToUser);
        LOGGER.debug("BytesAvailableToUser: {}", bytesAvailableToUser);

        long unusedBytesAvailableToUser = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setUnusedBytesAvailableToUser(unusedBytesAvailableToUser);
        LOGGER.debug("UnusedBytesAvailableToUser: {}", unusedBytesAvailableToUser);

        int bytesPerAllocationUnit = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setBytesPerAllocationUnit(bytesPerAllocationUnit);
        LOGGER.debug("BytesPerAllocationUnit: {}", bytesPerAllocationUnit);
    }
}
