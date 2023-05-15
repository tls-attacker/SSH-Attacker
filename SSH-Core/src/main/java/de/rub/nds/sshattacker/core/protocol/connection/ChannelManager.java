/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.stream.IntStream;

public class ChannelManager {

    private static final Logger LOGGER = LogManager.getLogger();
    private final HashMap<Integer, Channel> channels = new HashMap<>();

    private final SshContext context;

    private final List<ChannelOpenConfirmationMessage> pendingChannelOpenConfirmations =
            new LinkedList<>();

    private final List<ChannelMessage<?>> channelRequestResponseQueue = new LinkedList<>();

    public ChannelManager(SshContext context) {
        super();
        this.context = context;
    }

    /**
     * Find the next unused channel ID.
     *
     * <p>At the moment, the channel management on server side is just done by a default counter.
     * Thus, the channel manager iterates through the channels, searching for the first non-existing
     * index. If all channels ids exist up to the number of channels, the channel index
     * numberOfChannels + 1 will be opened.
     */
    private int findUnusedChannelId() {
        return IntStream.iterate(0, i -> i + 1)
                .filter(i -> channels.get(i) == null)
                .findFirst()
                .orElseThrow(); // should never occur with infinite stream
    }

    public void handleChannelOpenMessage(ChannelOpenMessage<?> message) {
        Channel channel = createNewChannelFromDefaults(message.getSenderChannelId().getValue());
        channel.setChannelType(ChannelType.fromName(message.getChannelType().getValue()));
        channel.setRemoteWindowSize(message.getWindowSize());
        channel.setRemotePacketSize(message.getPacketSize());
        // channel is closed until OpenConfirm is sent
        channel.setOpen(false);

        // prepare the response ChannelOpenConfirm and queue it
        ChannelOpenConfirmationMessage confirmation = new ChannelOpenConfirmationMessage();
        confirmation.setSenderChannelId(channel.getLocalChannelId());
        confirmation.setRecipientChannelId(channel.getRemoteChannelId());
        pendingChannelOpenConfirmations.add(confirmation);
    }

    public ChannelOpenConfirmationMessage prepareNextOpenConfirm() {
        if (!pendingChannelOpenConfirmations.isEmpty()) {
            return pendingChannelOpenConfirmations.remove(0);
        }
        ChannelOpenConfirmationMessage fresh = new ChannelOpenConfirmationMessage();
        guessChannelByReceivedMessages()
                .ifPresentOrElse(
                        channel -> {
                            fresh.setSenderChannelId(channel.getLocalChannelId());
                            fresh.setRecipientChannelId(channel.getRemoteChannelId());
                        },
                        () -> {
                            LOGGER.error(
                                    "Failed to guess channel, setting sender and receiver channel IDs to 0!");
                            fresh.setSenderChannelId(0);
                            fresh.setRecipientChannelId(0);
                        });
        return fresh;
    }

    public HashMap<Integer, Channel> getChannels() {
        return channels;
    }

    /**
     * Create a new channel from the configured defaults and add it to the channel map.
     *
     * @param localChannelId the local channel ID
     * @param remoteChannelId the remote channel ID
     * @return the created channel
     */
    private Channel createNewChannelFromDefaults(int localChannelId, int remoteChannelId) {
        Channel channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
        channel.setLocalChannelId(localChannelId);
        channel.setRemoteChannelId(remoteChannelId);
        channels.put(remoteChannelId, channel);
        return channel;
    }

    /**
     * Create a new channel from the configured defaults and add it to the channel map.
     *
     * <p>This is a convenience method that selects the next free local channel ID automatically.
     *
     * @param remoteChannelId the remote channel ID
     * @return the created channel
     */
    public Channel createNewChannelFromDefaults(int remoteChannelId) {
        int localChannelId = findUnusedChannelId();
        return createNewChannelFromDefaults(localChannelId, remoteChannelId);
    }

    public Optional<Channel> guessChannelByReceivedMessages() {
        if (!channelRequestResponseQueue.isEmpty()) {
            ChannelMessage<?> message = channelRequestResponseQueue.remove(0);
            for (Integer object : channels.keySet()) {
                if (Objects.equals(
                        channels.get(object).getLocalChannelId().getValue(),
                        message.getRecipientChannelId().getValue())) {
                    return Optional.ofNullable(channels.get(object));
                }
            }
        }
        return channels.values().stream().findFirst();
    }

    public void addToChannelRequestResponseQueue(ChannelMessage<?> message) {
        channelRequestResponseQueue.add(message);
    }
}
