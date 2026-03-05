/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

public abstract class SshMessageParser<T extends SshMessage<T>> extends ProtocolMessageParser<T> {

    protected SshMessageParser(byte[] array) {
        super(array);
    }

    protected SshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseMessageID() {
        message.setMessageId(parseByteField());
    }

    @Override
    protected final void parseProtocolMessageContents() {
        parseMessageID();
        parseMessageSpecificContents();
    }

    protected abstract void parseMessageSpecificContents();
}
