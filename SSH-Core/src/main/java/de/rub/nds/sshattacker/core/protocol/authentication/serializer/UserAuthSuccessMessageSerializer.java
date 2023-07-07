/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;

public class UserAuthSuccessMessageSerializer extends SshMessageSerializer<UserAuthSuccessMessage> {

    public UserAuthSuccessMessageSerializer(UserAuthSuccessMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {}

    @Override
    protected byte[] serializeBytes() {
        serializeProtocolMessageContents();
        return getAlreadySerialized();
    }
}
