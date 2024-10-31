/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestOpendirMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestOpendirMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestOpendirMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestOpendirMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestOpendirMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestOpendirMessage createMessage() {
        return new SftpRequestOpendirMessage();
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        // TODO parserSftpRequestOpendirMessage();
    }
}
