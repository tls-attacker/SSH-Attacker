/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;

public abstract class SftpMessageSerializer<T extends SftpMessage<T>>
        extends ProtocolMessageSerializer<T> {

    protected SftpMessageSerializer(T message) {
        super(message);
    }

    @Override
    protected final void serializeProtocolMessageContents() {
        appendByte(message.getPacketType().getValue());
        serializeMessageSpecificContents();
    }

    protected abstract void serializeMessageSpecificContents();
}
