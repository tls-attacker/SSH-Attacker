/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;

public class ChannelRequestExecMessagePreparator
        extends SshMessagePreparator<ChannelRequestExecMessage> {

    public ChannelRequestExecMessagePreparator(Chooser chooser, ChannelRequestExecMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_REQUEST);
        Optional<Integer> remoteChannel = chooser.getContext().getRemoteChannel();
        if (remoteChannel.isPresent()) {
            getObject().setRecipientChannel(remoteChannel.get());
        } else {
            raisePreparationException(
                    "Unable to prepare ChannelRequestExecMessage - No remote channel id set");
            getObject().setRecipientChannel(0);
        }
        getObject().setWantReply(chooser.getConfig().getReplyWanted());
        getObject().setRequestType(ChannelRequestType.EXEC, true);
        getObject().setCommand(chooser.getConfig().getChannelCommand(), true);
    }
}
