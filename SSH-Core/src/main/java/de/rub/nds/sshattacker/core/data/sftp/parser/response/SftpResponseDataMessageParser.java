/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.response;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseDataMessage;
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
        int dataLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setDataLength(dataLength);
        LOGGER.debug("Data length: {}", dataLength);
        byte[] data = parseByteArrayField(dataLength);
        message.setData(data);
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToHexString(data));
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseData();
    }
}
