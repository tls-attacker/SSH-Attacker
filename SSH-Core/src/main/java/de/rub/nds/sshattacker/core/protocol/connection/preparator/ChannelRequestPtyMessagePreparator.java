/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.exceptions.MissingChannelException;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestPtyMessagePreparator
        extends SshMessagePreparator<ChannelRequestPtyMessage> {

    public ChannelRequestPtyMessagePreparator(Chooser chooser, ChannelRequestPtyMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {

        if (getObject().getSenderChannel() == null) {
            throw new PreparationException("Sender channel required to send the message!");
        }
        Channel channel = chooser.getContext().getChannels().get(getObject().getSenderChannel());
        if (channel == null) {
            throw new MissingChannelException("Can't find the required channel!");
        } else if (channel.isOpen().getValue()) {
            getObject()
                    .setRecipientChannel(
                            Channel.getLocal_remote().get(getObject().getSenderChannel()));
            getObject().setWantReply(chooser.getConfig().getReplyWanted());
            getObject().setTermEnvVariable(chooser.getConfig().getDefaultTermEnvVariable(), true);
            getObject().setRequestType(ChannelRequestType.PTY_REQ, true);
            getObject().setWidthCharacters(chooser.getConfig().getDefaultTerminalWidthColumns());
            getObject().setHeightRows(chooser.getConfig().getDefaultTerminalHeightRows());
            getObject().setWidthPixels(chooser.getConfig().getDefaultTerminalWidthPixels());
            getObject().setHeightPixels(chooser.getConfig().getDefaultTerminalHeightPixels());
            getObject().setEncodedTerminalModes("", true);
        } else {
            throw new MissingChannelException("Required channel is closed!");
        }
    }
}
