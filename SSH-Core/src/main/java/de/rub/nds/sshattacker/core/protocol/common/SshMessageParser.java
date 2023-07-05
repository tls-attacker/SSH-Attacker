/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.constants.SshMessageConstants;
import java.io.InputStream;

public abstract class SshMessageParser<T extends SshMessage<T>> extends ProtocolMessageParser<T> {

    /*public SshMessageParser(byte[] array) {
        super(array);
    }

    public SshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/

    public SshMessageParser(InputStream stream) {
        super(stream);
    }

    /*@Override*/
    protected final void parseProtocolMessageContents(T message) {
        parseMessageID(message);
        parseMessageSpecificContents(message);
    }

    private void parseMessageID(T message) {
        message.setMessageId(parseByteField(SshMessageConstants.MESSAGE_ID_LENGTH));
    }

    protected abstract void parseMessageSpecificContents(T message);
}
