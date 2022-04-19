/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestPtyMessagePreparator
        extends SshMessagePreparator<ChannelRequestPtyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestPtyMessagePreparator(Chooser chooser, ChannelRequestPtyMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        Channel channel = null;
        if (getObject().getSenderChannel() != null) {
            channel = chooser.getContext().getChannels().get(getObject().getSenderChannel());
        }

        if (channel == null) {
            channel = chooser.getConfig().getDefaultChannel();
        }
        if (!channel.isOpen().getValue()) {
            LOGGER.info("The required channel is closed, still sending the message!");
        }
        getObject().setRecipientChannel(channel.getRemoteChannel());
        getObject().setWantReply(chooser.getConfig().getReplyWanted());
        getObject().setTermEnvVariable(chooser.getConfig().getDefaultTermEnvVariable(), true);
        getObject().setRequestType(ChannelRequestType.PTY_REQ, true);
        getObject().setWidthCharacters(chooser.getConfig().getDefaultTerminalWidthColumns());
        getObject().setHeightRows(chooser.getConfig().getDefaultTerminalHeightRows());
        getObject().setWidthPixels(chooser.getConfig().getDefaultTerminalWidthPixels());
        getObject().setHeightPixels(chooser.getConfig().getDefaultTerminalHeightPixels());
        getObject().setEncodedTerminalModes("", true);
    }
}
