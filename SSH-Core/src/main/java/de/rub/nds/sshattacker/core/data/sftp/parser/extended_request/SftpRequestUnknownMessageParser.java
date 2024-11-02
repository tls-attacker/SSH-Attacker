/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestUnknownMessageParser
        extends SftpRequestExtendedMessageParser<SftpRequestUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestUnknownMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestUnknownMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestUnknownMessage createMessage() {
        return new SftpRequestUnknownMessage();
    }

    private void parseRequestSpecificData() {
        message.setRequestSpecificData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "RequestSpecificData: {}",
                () ->
                        ArrayConverter.bytesToRawHexString(
                                message.getRequestSpecificData().getValue()));
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {
        parseRequestSpecificData();
    }
}
