/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended;

import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestLinkSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.attribute.SftpFileAttributesParser;

public class SftpRequestLinkSetStatMessageParser
        extends SftpRequestExtendedWithPathMessageParser<SftpRequestLinkSetStatMessage> {

    public SftpRequestLinkSetStatMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestLinkSetStatMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestLinkSetStatMessage createMessage() {
        return new SftpRequestLinkSetStatMessage();
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestExtendedWithPathSpecificContents() {
        parseAttributes();
    }
}
