/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.ChannelDataType;
import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpInitMessage;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpVersionMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelManager;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelCloseMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelCloseMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelCloseMessageHandler extends SshMessageHandler<ChannelCloseMessage>
        implements MessageSentHandler<ChannelCloseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, ChannelCloseMessage object) {
        ChannelManager channelManager = context.getChannelManager();
        Integer recipientChannelId = object.getRecipientChannelId().getValue();
        Channel channel = channelManager.getChannelByLocalId(recipientChannelId);
        if (channel != null) {
            if (!channel.isOpen().getValue()) {
                LOGGER.warn(
                        "{} received but channel with id {} is not open, continuing anyway.",
                        object.getClass().getSimpleName(),
                        recipientChannelId);
            } else {
                LOGGER.warn(
                        "{} received for channel with id {}",
                        object.getClass().getSimpleName(),
                        recipientChannelId);
                channel.setCloseMessageReceived(true);
                if (!channel.isOpen().getValue()) {
                    channelManager.removeChannelByLocalId(recipientChannelId);
                } else {
                    // The channel is still open, because we have not yet closed it.
                    generateDynamicActions(context, channel);
                }
            }
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring request to close the channel.",
                    object.getClass().getSimpleName(),
                    recipientChannelId);
        }
    }

    private static void generateDynamicActions(SshContext context, Channel channel) {
        Config config = context.getConfig();
        if (config.getAllowDynamicGenerationOfActions()
                && config.getReopenChannelOnClose()
                && config.getDefaultRunningMode() == RunningModeType.CLIENT) {

            // Generate actions to close the channel and reopen it.
            String connectionAlias = config.getDefaultClientConnection().getAlias();
            if (channel.getChannelType() == ChannelType.SESSION) {

                context.addDynamicGeneratedAction(
                        new SendAction(
                                connectionAlias,
                                new ChannelCloseMessage(channel.getLocalChannelId().getValue()),
                                new ChannelOpenSessionMessage(
                                        channel.getLocalChannelId().getValue())));
                context.addDynamicGeneratedAction(
                        new ReceiveAction(connectionAlias, new ChannelOpenConfirmationMessage()));

                if (channel.getExpectedDataType() == ChannelDataType.SUBSYSTEM_SFTP) {
                    context.addDynamicGeneratedAction(
                            new SendAction(connectionAlias, new ChannelRequestSubsystemMessage()));
                    context.addDynamicGeneratedAction(
                            new ReceiveAction(connectionAlias, new ChannelSuccessMessage()));
                    context.addDynamicGeneratedAction(
                            new SendAction(connectionAlias, new SftpInitMessage()));
                    context.addDynamicGeneratedAction(
                            new ReceiveAction(connectionAlias, new SftpVersionMessage()));
                }
            }
        }
    }

    @Override
    public void adjustContextAfterMessageSent(SshContext context, ChannelCloseMessage object) {
        ChannelManager channelManager = context.getChannelManager();
        Integer recipientChannelId = object.getRecipientChannelId().getValue();
        Channel channel = channelManager.getChannelByRemoteId(recipientChannelId);
        if (channel != null) {
            channel.setCloseMessageSent(true);
            if (!channel.isOpen().getValue()) {
                channelManager.removeChannelByRemoteId(recipientChannelId);
            }
        } else {
            LOGGER.warn(
                    "{} sent but no channel with remote id {} found, ignoring request to close the channel.",
                    getClass().getSimpleName(),
                    recipientChannelId);
        }
    }

    @Override
    public ChannelCloseMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelCloseMessageParser(array);
    }

    @Override
    public ChannelCloseMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelCloseMessageParser(array, startPosition);
    }

    public static final ChannelCloseMessagePreparator PREPARATOR =
            new ChannelCloseMessagePreparator();

    public static final ChannelMessageSerializer<ChannelCloseMessage> SERIALIZER =
            new ChannelMessageSerializer<>();
}
