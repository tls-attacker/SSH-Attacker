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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelFailureMessagePreparator extends SshMessagePreparator<ChannelFailureMessage> {

    public ChannelFailureMessagePreparator(SshContext context, ChannelFailureMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_FAILURE);
        // TODO: Dummy values for fuzzing
        getObject().setRecipientChannel(Integer.MAX_VALUE);
    }
}
