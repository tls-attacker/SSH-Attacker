/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestWithPathMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestOpenMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.holder.SftpV4FileAttributesParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4RequestOpenMessageParser
        extends SftpRequestWithPathMessageParser<SftpV4RequestOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpV4RequestOpenMessageParser(byte[] array) {
        super(array);
    }

    public SftpV4RequestOpenMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpV4RequestOpenMessage createMessage() {
        return new SftpV4RequestOpenMessage();
    }

    private void parseOpenFlags() {
        int openFlags = parseIntField();
        message.setOpenFlags(openFlags);
        LOGGER.debug("OpenFlags: {}", openFlags);
    }

    private void parseAttributes() {
        SftpV4FileAttributesParser attributesParser =
                new SftpV4FileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parseOpenFlags();
        parseAttributes();
    }
}
