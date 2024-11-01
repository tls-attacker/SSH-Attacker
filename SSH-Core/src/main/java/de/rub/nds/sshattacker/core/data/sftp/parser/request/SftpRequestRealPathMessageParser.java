/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRealPathMessage;

public class SftpRequestRealPathMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestRealPathMessage> {

    public SftpRequestRealPathMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestRealPathMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestRealPathMessage createMessage() {
        return new SftpRequestRealPathMessage();
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {}
}
