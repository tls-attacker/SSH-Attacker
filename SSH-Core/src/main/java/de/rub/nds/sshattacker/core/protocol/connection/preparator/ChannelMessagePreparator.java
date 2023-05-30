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
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelMessagePreparator<T extends ChannelMessage<T>>
        extends SshMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Channel channel;

    protected ChannelMessagePreparator(Chooser chooser, T message, MessageIdConstant messageId) {
        super(chooser, message, messageId);
    }

    @Override
    public final void prepareMessageSpecificContents() {
        prepareChannel();
        prepareChannelMessageSpecificContents();
    }

    private void prepareChannel() {
        Optional<Integer> configSenderChannelId =
                Optional.ofNullable(getObject().getConfigSenderChannelId());
        channel =
                configSenderChannelId
                        .flatMap(
                                senderChannelId ->
                                        Optional.ofNullable(
                                                chooser.getContext()
                                                        .getChannels()
                                                        .get(senderChannelId)))
                        .or(
                                () ->
                                        chooser.getContext()
                                                .getChannelManager()
                                                .guessChannelByReceivedMessages())
                        .orElseGet(
                                () -> {
                                    LOGGER.warn(
                                            "About to prepare channel message, but no corresponding was channel found or guessed. Creating a new one from defaults.");
                                    Integer remoteChannelId = configSenderChannelId.orElse(0);
                                    return chooser.getContext()
                                            .getChannelManager()
                                            .createNewChannelFromDefaults(remoteChannelId);
                                });

        if (!channel.isOpen().getValue()) {
            int localChannelId = channel.getLocalChannelId().getValue();
            LOGGER.warn(
                    "About to prepare channel message for channel with local id {}, but channel is not open. Continuing anyway.",
                    localChannelId);
        }
        getObject().setRecipientChannelId(channel.getRemoteChannelId());
    }

    protected abstract void prepareChannelMessageSpecificContents();
}
