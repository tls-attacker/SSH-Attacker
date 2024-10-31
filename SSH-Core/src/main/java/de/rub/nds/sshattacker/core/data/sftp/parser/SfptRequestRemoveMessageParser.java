/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestRemoveMessage;

public class SfptRequestRemoveMessageParser
        extends SftpRequestWithPathMessageParser<SfptRequestRemoveMessage> {

    public SfptRequestRemoveMessageParser(byte[] array) {
        super(array);
    }

    public SfptRequestRemoveMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SfptRequestRemoveMessage createMessage() {
        return new SfptRequestRemoveMessage();
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {}
}
