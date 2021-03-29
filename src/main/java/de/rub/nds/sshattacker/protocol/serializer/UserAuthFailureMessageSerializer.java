/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.util.Converter;

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
