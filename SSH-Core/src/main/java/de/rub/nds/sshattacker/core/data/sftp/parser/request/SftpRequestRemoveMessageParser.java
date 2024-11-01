/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRemoveMessage;

public class SftpRequestRemoveMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestRemoveMessage> {

    public SftpRequestRemoveMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestRemoveMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestRemoveMessage createMessage() {
        return new SftpRequestRemoveMessage();
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {}
}
