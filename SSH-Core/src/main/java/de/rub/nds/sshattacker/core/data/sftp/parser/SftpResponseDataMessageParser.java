/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpResponseDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseDataMessageParser
        extends SftpResponseMessageParser<SftpResponseDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseDataMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseDataMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseDataMessage createMessage() {
        return new SftpResponseDataMessage();
    }

    private void parseData() {
        message.setDataLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Data length: {}", message.getDataLength().getValue());
        message.setData(parseByteArrayField(message.getDataLength().getValue()));
        LOGGER.debug(
                "Data: {}", () -> ArrayConverter.bytesToRawHexString(message.getData().getValue()));
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseData();
    }
}
