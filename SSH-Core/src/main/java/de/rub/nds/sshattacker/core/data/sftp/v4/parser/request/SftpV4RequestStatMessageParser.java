/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestWithPathMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestStatMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4RequestStatMessageParser
        extends SftpRequestWithPathMessageParser<SftpV4RequestStatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpV4RequestStatMessageParser(byte[] array) {
        super(array);
    }

    public SftpV4RequestStatMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpV4RequestStatMessage createMessage() {
        return new SftpV4RequestStatMessage();
    }

    private void parseFlags() {
        int flags = parseIntField();
        message.setFlags(flags);
        LOGGER.debug("Flags: {}", flags);
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parseFlags();
    }
}
