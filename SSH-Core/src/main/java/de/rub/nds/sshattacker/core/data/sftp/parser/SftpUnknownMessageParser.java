/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpUnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpUnknownMessageParser extends SftpMessageParser<SftpUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpUnknownMessageParser(byte[] array) {
        super(array);
    }

    public SftpUnknownMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpUnknownMessage createMessage() {
        return new SftpUnknownMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        message.setPayload(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Payload: {}",
                () -> ArrayConverter.bytesToRawHexString(message.getPayload().getValue()));
    }
}
