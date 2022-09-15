/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthNoneMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthNoneMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthNoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthNoneMessageSerializer(UserAuthNoneMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
    }
}
