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
import de.rub.nds.sshattacker.core.protocol.connection.ChannelManager;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelOpenMessagePreparator<T extends ChannelOpenMessage<T>>
        extends SshMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Channel channel;

    protected ChannelOpenMessagePreparator(Chooser chooser, T message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_OPEN);
    }

    @Override
    public void prepareMessageSpecificContents() {
        ChannelManager channelManager = chooser.getContext().getChannelManager();

        Integer localChannelId =
                Optional.ofNullable(getObject().getConfigLocalChannelId())
                        .orElse(chooser.getConfig().getChannelDefaults().getLocalChannelId());

        getObject().setSoftlySenderChannelId(localChannelId, chooser.getConfig());
        Integer senderChannelId = getObject().getSenderChannelId().getValue();

        channel = channelManager.getChannelByLocalId(senderChannelId);
        if (channel != null) {
            LOGGER.warn(
                    "Channel with id {} is already exists, reusing the existing channel object.",
                    senderChannelId);
            if (channel.isOpen().getValue()) {
                LOGGER.warn(
                        "Channel with id {} is already open, sending ChannelOpenMessage with current channel details again.",
                        senderChannelId);
            }
        } else {
            channel = channelManager.createPrendingChannel(senderChannelId);
        }
        getObject().setSoftlyChannelType(channel.getChannelType(), true, chooser.getConfig());
        getObject().setSoftlyWindowSize(channel.getLocalWindowSize().getValue());
        getObject().setSoftlyPacketSize(32768);
        prepareChannelOpenMessageSpecificContents();
    }

    protected abstract void prepareChannelOpenMessageSpecificContents();
}
