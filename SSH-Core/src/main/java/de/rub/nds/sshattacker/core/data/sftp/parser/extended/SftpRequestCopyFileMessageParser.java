/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestCopyFileMessage;
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
        message.setDestinationPathLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("DestinationPath length: {}", message.getDestinationPathLength().getValue());
        message.setDestinationPath(
                parseByteString(
                        message.getDestinationPathLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug(
                "DestinationPath: {}",
                () -> backslashEscapeString(message.getDestinationPath().getValue()));
    }

    private void parseOverwriteDestination() {
        message.setOverwriteDestination(parseByteField(1));
        LOGGER.debug("OverwriteDestination: {}", message.getOverwriteDestination().getValue());
    }

    @Override
    protected void parseRequestExtendedWithPathSpecificContents() {
        parseDestinationPath();
        parseOverwriteDestination();
    }
}
