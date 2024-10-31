/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestReadDirMessage;

public class SftpRequestReadDirMessageParser
        extends SftpRequestWithHandleMessageParser<SftpRequestReadDirMessage> {

    public SftpRequestReadDirMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestReadDirMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestReadDirMessage createMessage() {
        return new SftpRequestReadDirMessage();
    }

    @Override
    protected void parseRequestWithHandleSpecificContents() {}
}
