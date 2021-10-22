/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenMessagePreparator extends SshMessagePreparator<ChannelOpenMessage> {

    public ChannelOpenMessagePreparator(Chooser chooser, ChannelOpenMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_OPEN);
        getObject().setSenderChannel(chooser.getLocalChannel());
        getObject().setChannelType(chooser.getChannelType().toString(), true);
        getObject().setWindowSize(chooser.getWindowSize());
        getObject().setPacketSize(chooser.getPacketSize());
    }
}
