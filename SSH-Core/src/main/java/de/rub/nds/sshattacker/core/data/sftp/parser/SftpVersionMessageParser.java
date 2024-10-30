/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.data.sftp.message.SftpVersionMessage;

public class SftpVersionMessageParser extends SftpHandshakeMessageParser<SftpVersionMessage> {

    public SftpVersionMessageParser(byte[] array) {
        super(array);
    }

    public SftpVersionMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpVersionMessage createMessage() {
        return new SftpVersionMessage();
    }
}
