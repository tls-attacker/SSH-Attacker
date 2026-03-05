/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestOpenMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpFileAttributesParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestOpenMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestOpenMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestOpenMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestOpenMessage createMessage() {
        return new SftpRequestOpenMessage();
    }

    private void parseOpenFlags() {
        int openFlags = parseIntField();
        message.setOpenFlags(openFlags);
        LOGGER.debug("OpenFlags: {}", openFlags);
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parseOpenFlags();
        parseAttributes();
    }
}
