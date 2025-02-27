/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestExtendedMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestMessageParser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestExtendedMessageParser<T extends SftpRequestExtendedMessage<T>>
        extends SftpRequestMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestExtendedMessageParser(byte[] array) {
        super(array);
    }

    protected SftpRequestExtendedMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseExtendedRequestName() {
        int extendedRequestNameLength = parseIntField();
        message.setExtendedRequestNameLength(extendedRequestNameLength);
        LOGGER.debug("ExtendedRequestName length: {}", extendedRequestNameLength);
        String extendedRequestName =
                parseByteString(extendedRequestNameLength, StandardCharsets.US_ASCII);
        message.setExtendedRequestName(extendedRequestName);
        LOGGER.debug("ExtendedRequestName: {}", () -> backslashEscapeString(extendedRequestName));
    }

    @Override
    protected void parseRequestSpecificContents() {
        parseExtendedRequestName();
        parseRequestExtendedSpecificContents();
    }

    protected abstract void parseRequestExtendedSpecificContents();
}
