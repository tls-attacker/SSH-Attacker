/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestRmdirMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestRmdirMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestRmdirMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestRmdirMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestRmdirMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestRmdirMessage createMessage() {
        return new SftpRequestRmdirMessage();
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        // TODO parserSftpRequestRmdirMessage();
    }
}
