/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDefaultMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenDefaultMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenDefaultMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenDefaultMessageSerializer(ChannelOpenDefaultMessage message) {
        super(message);
    }
}
