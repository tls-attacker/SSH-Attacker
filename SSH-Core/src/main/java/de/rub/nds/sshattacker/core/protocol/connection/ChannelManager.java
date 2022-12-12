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
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelManager {

    private static final Logger LOGGER = LogManager.getLogger();
    private HashMap<Integer, Channel> channels = new HashMap<>();

    private SshContext context;

    private List<ChannelOpenConfirmationMessage> pendingChannelOpenConfirmations =
            new LinkedList<>();

    private List<ChannelMessage> channelRequestResponseQueue = new LinkedList<>();

    public ChannelManager(SshContext context) {
        this.context = context;
    }

    public void handleChannelOpenMessage(ChannelOpenMessage message) {
        Channel channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
        channel.setRemoteChannelId(message.getSenderChannelId().getValue());
        int freshChannelId = 0;
        /* At the moment the server is channel management on server side is just done by a default counter.
         * Thus the channel manager iterates through the channels, searching for the first non-existing index.
         * If all channels id's exist up to the number of channels, the channel index numberOfChannels+1 will be opened.*/
        for (int i = 0; i <= channels.size(); i++) {
            if (channels.get(i) == null) {
                freshChannelId = i;
                break;
            }
        }
        channel.setLocalChannelId(freshChannelId);
        channel.setChannelType(ChannelType.getByString(message.getChannelType().getValue()));
        channel.setRemoteWindowSize(message.getWindowSize());
        channel.setRemotePacketSize(message.getPacketSize());
        // channel is closed until OpenConfirm is send
        channel.setOpen(false);
        channels.put(message.getSenderChannelId().getValue(), channel);

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
        Channel channel = this.guessChannelByReceivedMessages();
        fresh.setSenderChannelId(channel.getLocalChannelId());
        fresh.setRecipientChannelId(channel.getRemoteChannelId());
        return fresh;
    }

    public HashMap<Integer, Channel> getChannels() {
        return channels;
    }

    public Channel guessChannelByReceivedMessages() {
        if (channelRequestResponseQueue.size() != 0) {
            ChannelMessage message = (ChannelMessage) channelRequestResponseQueue.remove(0);
            for (Integer object : channels.keySet()) {
                if (channels.get(object).getLocalChannelId().getValue()
                        == message.getRecipientChannelId().getValue()) {
                    return channels.get(object);
                }
            }
        }
        return channels.values().stream().findFirst().get();
    }

    public void addToChannelRequestResponseQueue(ChannelMessage message) {
        channelRequestResponseQueue.add(message);
    }
}
