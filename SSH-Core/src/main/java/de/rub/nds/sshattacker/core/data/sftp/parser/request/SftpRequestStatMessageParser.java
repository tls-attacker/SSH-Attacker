/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestStatMessage;

public class SftpRequestStatMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestStatMessage> {

    public SftpRequestStatMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestStatMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestStatMessage createMessage() {
        return new SftpRequestStatMessage();
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {}
}
