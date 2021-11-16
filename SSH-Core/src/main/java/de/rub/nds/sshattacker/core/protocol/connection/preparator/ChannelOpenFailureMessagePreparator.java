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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenFailureMessagePreparator
        extends SshMessagePreparator<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessagePreparator(
            SshContext context, ChannelOpenFailureMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_OPEN_FAILURE);
        // TODO dummy values for fuzzing
        getObject().setRecipientChannel(context.getChooser().getRemoteChannel());
        getObject().setReasonCode(Integer.MAX_VALUE);
        getObject().setReason("", true);
        getObject().setLanguageTag("", true);
    }
}
