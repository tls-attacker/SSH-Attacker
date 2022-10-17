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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessagePreparator
        extends SshMessagePreparator<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessagePreparator(
            Chooser chooser, ChannelOpenConfirmationMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    }

    @Override
    public void prepareMessageSpecificContents() {
        HashMap<Integer, Channel> channelMap = chooser.getContext().getChannels();
        ChannelDefaults channelDefaults = chooser.getConfig().getChannelDefaults();

        int channelId;
        if (getObject().getConfigSenderChannelId() != null) {
            channelId = getObject().getConfigSenderChannelId();
        } else {
            channelId = chooser.getConfig().getChannelDefaults().getLocalChannelId();
        }
        getObject().setSenderChannelId(channelId);
        Channel channel =
                chooser.getContext().getChannels().get(getObject().getSenderChannelId().getValue());
        if (channel != null && channel.isOpen().getValue()) {
            LOGGER.warn(
                    "Channel with id {} is already open, sending ChannelOpenConfirmationMessage with current channel details again.",
                    getObject().getSenderChannelId().getValue());
        } else {
            LOGGER.warn(
                    "Channel with id {} does not exist locally, creating a new one from defaults.",
                    getObject().getSenderChannelId().getValue());
            channel = channelDefaults.newChannelFromDefaults();
            channel.setLocalChannelId(getObject().getSenderChannelId().getValue());
            channelMap.put(getObject().getSenderChannelId().getValue(), channel);
        }

        getObject().setRecipientChannelId(channel.getRemoteChannelId());
        getObject().setWindowSize(channel.getLocalWindowSize());
        getObject().setPacketSize(channel.getLocalPacketSize());
        channel.setOpen(true);
    }
}
