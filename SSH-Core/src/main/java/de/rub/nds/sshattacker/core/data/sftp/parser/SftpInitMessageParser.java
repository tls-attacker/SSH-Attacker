/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpInitMessageParser extends SftpMessageParser<SftpInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpInitMessageParser(byte[] array) {
        super(array);
    }

    public SftpInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpInitMessage createMessage() {
        return new SftpInitMessage();
    }

    public void parseMessageSpecificContents() {
        parseVersion();
    }

    private void parseVersion() {
        message.setVersion(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Version: {}", message.getVersion().getValue());
    }
}
