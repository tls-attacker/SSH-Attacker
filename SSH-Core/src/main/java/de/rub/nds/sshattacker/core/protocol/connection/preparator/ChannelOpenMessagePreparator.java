/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelType;
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

    private final String channelType;

    protected ChannelOpenMessagePreparator(ChannelType channelType) {
        this(channelType.toString());
    }

    protected ChannelOpenMessagePreparator(String channelType) {
        super(MessageIdConstant.SSH_MSG_CHANNEL_OPEN);
        this.channelType = channelType;
    }

    @Override
    public void prepareMessageSpecificContents(T object, Chooser chooser) {
        ChannelManager channelManager = chooser.getContext().getChannelManager();

        Integer localChannelId =
                Optional.ofNullable(object.getConfigLocalChannelId())
                        .orElse(chooser.getConfig().getChannelDefaults().getLocalChannelId());

        object.setSoftlySenderChannelId(localChannelId, chooser.getConfig());
        Integer senderChannelId = object.getSenderChannelId().getValue();

        channel = channelManager.getChannelByLocalId(senderChannelId);
        if (channel != null) {
            LOGGER.warn(
                    "Channel with id {} already exists, reusing the existing channel object.",
                    senderChannelId);
            if (channel.isOpen().getValue()) {
                LOGGER.warn(
                        "Channel with id {} is already open, sending ChannelOpenMessage with current channel details again.",
                        senderChannelId);
            }
        } else {
            channel = channelManager.createPrendingChannel(senderChannelId);
        }
        channel.setChannelType(ChannelType.fromName(channelType));
        // Always set correct channel type -> Don't use soft set
        object.setChannelType(channelType, true);
        object.setSoftlyWindowSize(channel.getLocalWindowSize().getValue());
        object.setSoftlyPacketSize(32768);
        prepareChannelOpenMessageSpecificContents(object, chooser);
    }

    protected abstract void prepareChannelOpenMessageSpecificContents(T object, Chooser chooser);
}
