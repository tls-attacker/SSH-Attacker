/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCopyFileMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCopyFileMessageParser
        extends SftpRequestExtendedWithPathMessageParser<SftpRequestCopyFileMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestCopyFileMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestCopyFileMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestCopyFileMessage createMessage() {
        return new SftpRequestCopyFileMessage();
    }

    private void parseDestinationPath() {
        int destinationPathLength = parseIntField();
        message.setDestinationPathLength(destinationPathLength);
        LOGGER.debug("DestinationPath length: {}", destinationPathLength);
        String destinationPath = parseByteString(destinationPathLength, StandardCharsets.UTF_8);
        message.setDestinationPath(destinationPath);
        LOGGER.debug("DestinationPath: {}", () -> backslashEscapeString(destinationPath));
    }

    private void parseOverwriteDestination() {
        byte overwriteDestination = parseByteField();
        message.setOverwriteDestination(overwriteDestination);
        LOGGER.debug("OverwriteDestination: {}", overwriteDestination);
    }

    @Override
    protected void parseRequestExtendedWithPathSpecificContents() {
        parseDestinationPath();
        parseOverwriteDestination();
    }
}
