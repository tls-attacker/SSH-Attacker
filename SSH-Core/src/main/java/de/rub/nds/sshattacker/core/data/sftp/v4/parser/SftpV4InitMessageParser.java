/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.parser;

import de.rub.nds.sshattacker.core.data.sftp.common.parser.SftpHandshakeMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.SftpV4InitMessage;

public class SftpV4InitMessageParser extends SftpHandshakeMessageParser<SftpV4InitMessage> {

    public SftpV4InitMessageParser(byte[] array) {
        super(array);
    }

    public SftpV4InitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpV4InitMessage createMessage() {
        return new SftpV4InitMessage();
    }
}
