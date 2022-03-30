/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.connection.Channel;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.constants.SignalType;
import de.rub.nds.sshattacker.core.exceptions.MissingChannelException;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitSignalMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestExitSignalMessagePreperator
        extends SshMessagePreparator<ChannelRequestExitSignalMessage> {

    public ChannelRequestExitSignalMessagePreperator(
            Chooser chooser, ChannelRequestExitSignalMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_REQUEST);
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
            getObject().setWantReply((byte) 0);
            getObject().setRequestType(ChannelRequestType.SIGNAL, true);
            getObject().setSignalName(SignalType.SIGINT, true);
            getObject().setCoreDump(false);
            getObject().setErrorMessage("", true);
            getObject().setLanguageTag("", true);
        } else {
            throw new MissingChannelException("Required channel is closed!");
        }
    }
}
