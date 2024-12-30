/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_response;

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
        long bytesOnDevice = parseLongField();
        message.setBytesOnDevice(bytesOnDevice);
        LOGGER.debug("BytesOnDevice: {}", bytesOnDevice);

        long unusedBytesOnDevice = parseLongField();
        message.setUnusedBytesOnDevice(unusedBytesOnDevice);
        LOGGER.debug("UnusedBytesOnDevice: {}", unusedBytesOnDevice);

        long bytesAvailableToUser = parseLongField();
        message.setBytesAvailableToUser(bytesAvailableToUser);
        LOGGER.debug("BytesAvailableToUser: {}", bytesAvailableToUser);

        long unusedBytesAvailableToUser = parseLongField();
        message.setUnusedBytesAvailableToUser(unusedBytesAvailableToUser);
        LOGGER.debug("UnusedBytesAvailableToUser: {}", unusedBytesAvailableToUser);

        int bytesPerAllocationUnit = parseIntField();
        message.setBytesPerAllocationUnit(bytesPerAllocationUnit);
        LOGGER.debug("BytesPerAllocationUnit: {}", bytesPerAllocationUnit);
    }
}
