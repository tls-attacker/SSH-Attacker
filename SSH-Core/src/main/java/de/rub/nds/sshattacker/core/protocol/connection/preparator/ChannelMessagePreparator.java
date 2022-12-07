/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelMessagePreparator<T extends ChannelMessage<T>>
        extends SshMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Channel channel;

    public ChannelMessagePreparator(Chooser chooser, T message, MessageIdConstant messageId) {
        super(chooser, message, messageId);
    }

    @Override
    public final void prepareMessageSpecificContents() {
        this.prepareChannel();
        this.prepareChannelMessageSpecificContents();
    }

    private void prepareChannel() {
        Integer senderChannelId = null;
        if (getObject().getConfigSenderChannelId() != null) {
            channel =
                    chooser.getContext().getChannels().get(getObject().getConfigSenderChannelId());
        } else {
            channel = chooser.getContext().getChannelManager().getChannel();
        }

        if (channel == null) {
            LOGGER.warn(
                    "About to prepare channel message for channel with local id {}, but no such channel found. Creating a new one from defaults.",
                    senderChannelId);
            channel = chooser.getConfig().getChannelDefaults().newChannelFromDefaults();
            channel.setLocalChannelId(senderChannelId);
            chooser.getContext().getChannels().put(senderChannelId, channel);
        }
        if (!channel.isOpen().getValue()) {
            LOGGER.warn(
                    "About to prepare channel message for channel with local id {}, but channel is not open. Continuing anyway.",
                    senderChannelId);
        }
        getObject().setRecipientChannelId(channel.getRemoteChannelId());
    }

    protected abstract void prepareChannelMessageSpecificContents();
}
