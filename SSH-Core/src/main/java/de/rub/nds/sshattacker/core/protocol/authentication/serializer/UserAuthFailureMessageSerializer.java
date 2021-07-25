/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;

public class UserAuthFailureMessageSerializer extends MessageSerializer<UserAuthFailureMessage> {

    public UserAuthFailureMessageSerializer(UserAuthFailureMessage msg) {
        super(msg);
    }

    private void serializePossibleAuthenticationMethods() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getPossibleAuthenticationMethods().getValue()));
    }

    private void serializePartialSuccess() {
        appendByte(msg.getPartialSuccess().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializePossibleAuthenticationMethods();
        serializePartialSuccess();
        return getAlreadySerialized();
    }

}
