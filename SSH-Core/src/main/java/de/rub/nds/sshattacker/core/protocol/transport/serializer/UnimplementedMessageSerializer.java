/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;

public class UnimplementedMessageSerializer extends SshMessageSerializer<UnimplementedMessage> {

    public UnimplementedMessageSerializer(UnimplementedMessage message) {
        super(message);
    }

    private void serializeSequenceNumber() {
        appendInt(message.getSequenceNumber().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeSequenceNumber();
    }
}
