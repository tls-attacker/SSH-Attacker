/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_response;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.response.SftpResponseMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseUnknownMessageParser
        extends SftpResponseMessageParser<SftpResponseUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseUnknownMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseUnknownMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseUnknownMessage createMessage() {
        return new SftpResponseUnknownMessage();
    }

    @Override
    protected void parseResponseSpecificContents() {
        message.setResponseSpecificData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "ResponseSpecificData: {}",
                () ->
                        ArrayConverter.bytesToRawHexString(
                                message.getResponseSpecificData().getValue()));
    }
}
