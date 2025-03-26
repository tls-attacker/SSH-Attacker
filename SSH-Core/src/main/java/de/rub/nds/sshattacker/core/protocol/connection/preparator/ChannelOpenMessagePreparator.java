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
import de.rub.nds.sshattacker.core.protocol.connection.ChannelDefaults;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelOpenMessagePreparator<T extends ChannelOpenMessage<T>>
        extends SshMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ChannelOpenMessagePreparator(Chooser chooser, T message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_OPEN);
    }

    @Override
    public void prepareMessageSpecificContents() {
        HashMap<Integer, Channel> channelMap = chooser.getContext().getChannels();
        ChannelDefaults channelDefaults = chooser.getConfig().getChannelDefaults();

        int channelId;
        if (getObject().getConfigSenderChannelId() != null) {
            channelId = getObject().getConfigSenderChannelId();
        } else {
            channelId = channelDefaults.getLocalChannelId();
        }
        getObject().setSenderChannelId(channelId);
        Channel channel =
                chooser.getContext().getChannels().get(getObject().getSenderChannelId().getValue());
        if (channel != null) {
            LOGGER.warn(
                    "Channel with id {} is already exists, reusing the existing channel object.",
                    getObject().getSenderChannelId().getValue());
            if (channel.isOpen().getValue()) {
                LOGGER.warn(
                        "Channel with id {} is already open, sending ChannelOpenMessage with current channel details again.",
                        getObject().getSenderChannelId().getValue());
            }
        } else {
            channel = channelDefaults.newChannelFromDefaults();
            channel.setLocalChannelId(getObject().getSenderChannelId().getValue());
            channelMap.put(getObject().getSenderChannelId().getValue(), channel);
        }
        getObject().setChannelType(channel.getChannelType(), true);
        getObject().setInitialWindowSize(channel.getLocalWindowSize());
        getObject().setMaximumPacketSize(32768);
        prepareChannelOpenMessageSpecificContents();
    }

    protected abstract void prepareChannelOpenMessageSpecificContents();
}
