/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestLinkStatMessage;

public class SftpRequestLinkStatMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestLinkStatMessage> {

    public SftpRequestLinkStatMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestLinkStatMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestLinkStatMessage createMessage() {
        return new SftpRequestLinkStatMessage();
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {}
}
