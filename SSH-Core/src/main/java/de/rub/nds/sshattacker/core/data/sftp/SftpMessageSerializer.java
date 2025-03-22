/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;

public abstract class SftpMessageSerializer<T extends SftpMessage<T>>
        extends ProtocolMessageSerializer<T> {

    @Override
    protected final void serializeProtocolMessageContents(T object, SerializerStream output) {
        output.appendByte(object.getPacketType().getValue());
        serializeMessageSpecificContents(object, output);
    }

    protected abstract void serializeMessageSpecificContents(T object, SerializerStream output);
}
