/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.connection.message.RequestSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;

public class RequestSuccessMessageSerializer extends MessageSerializer<RequestSuccessMessage> {

    public RequestSuccessMessageSerializer(RequestSuccessMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        appendBytes(msg.getPayload().getValue());
        return getAlreadySerialized();
    }

}
