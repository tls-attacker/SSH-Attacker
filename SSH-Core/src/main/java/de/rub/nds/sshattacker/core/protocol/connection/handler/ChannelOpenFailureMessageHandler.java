/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenFailureMessageHandler extends SshMessageHandler<ChannelOpenFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenFailureMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ChannelOpenFailureMessage message) {
        if (!sshContext.getChannels().containsKey(message.getRecipientChannelId().getValue())) {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring it.",
                    getClass().getSimpleName(),
                    message.getRecipientChannelId().getValue());
        }
        sshContext.getChannels().remove(message.getRecipientChannelId().getValue());
    }
}
