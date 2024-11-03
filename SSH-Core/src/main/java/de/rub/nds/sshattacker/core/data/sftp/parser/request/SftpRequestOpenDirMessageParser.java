/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestOpenDirMessage;

public class SftpRequestOpenDirMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestOpenDirMessage> {

    public SftpRequestOpenDirMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestOpenDirMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestOpenDirMessage createMessage() {
        return new SftpRequestOpenDirMessage();
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {}
}
