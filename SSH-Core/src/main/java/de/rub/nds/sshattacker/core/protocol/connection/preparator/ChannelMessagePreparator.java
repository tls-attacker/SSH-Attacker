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
import de.rub.nds.sshattacker.core.protocol.connection.ChannelManager;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelMessagePreparator<T extends ChannelMessage<T>>
        extends SshMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Channel channel;

    protected ChannelMessagePreparator(MessageIdConstant messageId) {
        super(messageId);
    }

    @Override
    public final void prepareMessageSpecificContents(T object, Chooser chooser) {
        prepareChannel(object, chooser);
        prepareChannelMessageSpecificContents(object, chooser);
    }

    private void prepareChannel(T object, Chooser chooser) {
        ChannelManager channelManager = chooser.getContext().getChannelManager();

        ChannelDefaults channelDefaults = chooser.getConfig().getChannelDefaults();
        Integer localChannelId =
                Optional.ofNullable(object.getConfigLocalChannelId())
                        .orElse(channelDefaults.getLocalChannelId());

        // ChannelMessages should only be sent for an opened channel
        channel =
                Optional.ofNullable(channelManager.getChannelByLocalId(localChannelId))
                        .or(channelManager::getChannelByReceivedRequestThatWantReply)
                        .orElseGet(
                                () -> {
                                    LOGGER.warn(
                                            "About to prepare channel message, but no corresponding channel was found or guessed. Creating a new channel from defaults. The other party will not know this channel either.");
                                    Integer remoteChannelId =
                                            Optional.ofNullable(object.getConfigRemoteChannelId())
                                                    .orElse(channelDefaults.getRemoteChannelId());
                                    return channelManager.createNewChannelFromDefaults(
                                            localChannelId, remoteChannelId);
                                });

        if (!channel.isOpen().getValue()) {
            LOGGER.warn(
                    "About to prepare channel message for channel with local id {}, but channel is not open. Continuing anyway.",
                    channel.getLocalChannelId().getValue());
        }
        object.setSoftlyRecipientChannelId(
                channel.getRemoteChannelId().getValue(), chooser.getConfig());
    }

    protected abstract void prepareChannelMessageSpecificContents(T object, Chooser chooser);
}
