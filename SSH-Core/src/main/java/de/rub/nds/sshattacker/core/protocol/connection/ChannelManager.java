/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.exceptions.ChannelManagerException;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.*;
import java.util.stream.IntStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelManager {

    private static final Logger LOGGER = LogManager.getLogger();

    // Open channels accessible via remote channel number (recipient channel ID for outgoing
    // messages)
    private final HashMap<Integer, Channel> channelsByRemoteId = new HashMap<>();
    // Open channels accessible via local channel number (recipient channel ID of incoming messages)
    private final HashMap<Integer, Channel> channelsByLocalId = new HashMap<>();

    // Pending channels that were requested (by the client) but not confirmed
    private final HashMap<Integer, Channel> pendingChannelsByLocalId = new HashMap<>();

    private final SshContext context;

    private final List<ChannelOpenConfirmationMessage> pendingChannelOpenConfirmations =
            new LinkedList<>();

    // Received channel requests that want a reply
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
                .filter(i -> channelsByLocalId.get(i) == null)
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
        // Create a new ChannelOpenConfirmationMessage, that is not a reply to a ChannelOpenMessage
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
        createNewChannelFromDefaults(
                fresh.getSenderChannelId().getValue(), fresh.getRecipientChannelId().getValue());
        return fresh;
    }

    public Channel getChannelByRemoteId(Integer remoteId) {
        return channelsByRemoteId.get(remoteId);
    }

    public Channel getChannelByLocalId(Integer localId) {
        return channelsByLocalId.get(localId);
    }

    public Channel removeChannelByRemoteId(Integer remoteId) {
        Channel channelRemoved = channelsByRemoteId.remove(remoteId);
        if (channelRemoved != null) {
            channelsByLocalId.remove(channelRemoved.getLocalChannelId().getValue());
        }
        return channelRemoved;
    }

    public Channel removeChannelByLocalId(Integer remoteId) {
        Channel channelRemoved = channelsByLocalId.remove(remoteId);
        if (channelRemoved != null) {
            channelsByRemoteId.remove(channelRemoved.getRemoteChannelId().getValue());
        }
        return channelRemoved;
    }

    public void addChannel(Channel channel) {
        if (channel.getRemoteChannelId().getValue() == null
                || channel.getLocalChannelId().getValue() == null) {
            throw new ChannelManagerException(
                    "Channel cannot be managed. Either the local or remote channel ID is not set");
        }
        channelsByRemoteId.put(channel.getRemoteChannelId().getValue(), channel);
        channelsByLocalId.put(channel.getLocalChannelId().getValue(), channel);
    }

    public boolean containsChannelWithLocalId(Integer localId) {
        return channelsByLocalId.containsKey(localId);
    }

    public boolean containsChannelWithRemoteId(Integer remoteId) {
        return channelsByRemoteId.containsKey(remoteId);
    }

    public Channel getPendingChannelByLocalId(Integer localId) {
        return pendingChannelsByLocalId.get(localId);
    }

    public void addPendingChannel(Channel channel) {
        if (channel.getLocalChannelId().getValue() == null) {
            throw new ChannelManagerException(
                    "Pending channel cannot have an empty the local channel ID");
        }
        pendingChannelsByLocalId.put(channel.getLocalChannelId().getValue(), channel);
    }

    public Channel removePendingChannelByLocalId(Integer localId) {
        return pendingChannelsByLocalId.remove(localId);
    }

    public Channel removePendingChannel(Channel channel) {
        return pendingChannelsByLocalId.remove(channel.getLocalChannelId().getValue());
    }

    public boolean containsPendingChannelWithLocalId(Integer localId) {
        return pendingChannelsByLocalId.containsKey(localId);
    }

    public void confirmPendingChannel(Channel channel) {
        removePendingChannel(channel);
        addChannel(channel);
    }

    /**
     * Create a new channel from the configured defaults and add it to the channel map.
     *
     * @param localChannelId the local channel ID
     * @param remoteChannelId the remote channel ID
     * @return the created channel
     */
    public Channel createNewChannelFromDefaults(int localChannelId, int remoteChannelId) {
        Channel channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
        channel.setLocalChannelId(localChannelId);
        channel.setRemoteChannelId(remoteChannelId);
        addChannel(channel);
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
        return createNewChannelFromDefaults(findUnusedChannelId(), remoteChannelId);
    }

    /**
     * Create a new pending channel from the configured defaults and add it to the pending channel
     * map. This channel is not yet confirmed, so it does not have a remote channel ID (recipient
     * Channel ID)
     *
     * @param localChannelId the local channel ID
     * @return the created pending channel
     */
    public Channel createPrendingChannel(int localChannelId) {
        Channel channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
        channel.setLocalChannelId(localChannelId);
        addPendingChannel(channel);
        return channel;
    }

    /**
     * Create a new pending channel from the configured defaults and add it to the pending channel
     * map. This channel is not yet confirmed, so it does not have a remote channel ID (recipient
     * Channel ID)
     *
     * <p>This is a convenience method that selects the next free local channel ID automatically.
     *
     * @return the created pending channel
     */
    public Channel createPrendingChannel() {
        return createPrendingChannel(findUnusedChannelId());
    }

    public Optional<Channel> guessChannelByReceivedMessages() {
        if (!channelRequestResponseQueue.isEmpty()) {
            ChannelMessage<?> message = channelRequestResponseQueue.remove(0);
            Optional.ofNullable(channelsByLocalId.get(message.getRecipientChannelId().getValue()));
        }
        return channelsByLocalId.values().stream().findFirst();
    }

    public void addToChannelRequestResponseQueue(ChannelMessage<?> message) {
        if (channelsByLocalId.containsKey(message.getRecipientChannelId().getValue())) {
            channelRequestResponseQueue.add(message);
        } else {
            LOGGER.warn(
                    "{} received but no channel with id {} found locally, ignoring it.",
                    message.getClass().getSimpleName(),
                    message.getRecipientChannelId().getValue());
        }
    }
}
