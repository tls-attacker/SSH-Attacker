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

    private List<ChannelOpenConfirmationMessage> nextToSend = new LinkedList<>();

    private List<ChannelMessage> responseQueue = new LinkedList<>();

    public ChannelManager(SshContext context) {
        this.context = context;
    }

    public void handleChannelOpenMessage(ChannelOpenMessage message) {
        Channel channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
        channel.setRemoteChannelId(message.getSenderChannelId().getValue());
        int freshChannelId = 0;
        // atm the server just Counts
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
        nextToSend.add(confirmation);
    }

    public ChannelOpenConfirmationMessage prepareNextOpenConfirm() {
        if (!nextToSend.isEmpty()) {
            return nextToSend.remove(0);
        }
        ChannelOpenConfirmationMessage fresh = new ChannelOpenConfirmationMessage();
        Channel channel = this.getChannel();
        fresh.setSenderChannelId(channel.getLocalChannelId());
        fresh.setRecipientChannelId(channel.getRemoteChannelId());
        return fresh;
    }

    public HashMap<Integer, Channel> getChannels() {
        return channels;
    }

    public Channel getChannel() {
        if (responseQueue.size() != 0) {
            ChannelMessage message = (ChannelMessage) responseQueue.remove(0);
            for (Integer object : channels.keySet()) {
                if (channels.get(object).getLocalChannelId().getValue()
                        == message.getRecipientChannelId().getValue()) {
                    return channels.get(object);
                }
            }
        }
        return channels.values().stream().findFirst().get();
    }

    public void addResponseQueue(ChannelMessage message) {
        responseQueue.add(message);
    }
}
