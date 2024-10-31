/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestMakeDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.attribute.SftpFileAttributesParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestMakeDirMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestMakeDirMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestMakeDirMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestMakeDirMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestMakeDirMessage createMessage() {
        return new SftpRequestMakeDirMessage();
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parseAttributes();
    }
}
