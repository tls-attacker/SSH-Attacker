/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestExtendedMessage;
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
        message.setExtendedRequestNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "ExtendedRequestName length: {}",
                message.getExtendedRequestNameLength().getValue());
        message.setExtendedRequestName(
                parseByteString(
                        message.getExtendedRequestNameLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "ExtendedRequestName: {}",
                () -> backslashEscapeString(message.getExtendedRequestName().getValue()));
    }

    @Override
    protected void parseRequestSpecificContents() {
        parseExtendedRequestName();
        parseRequestExtendedSpecificContents();
    }

    protected abstract void parseRequestExtendedSpecificContents();
}
