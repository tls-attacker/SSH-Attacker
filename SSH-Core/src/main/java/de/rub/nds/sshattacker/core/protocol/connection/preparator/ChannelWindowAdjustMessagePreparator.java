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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelWindowAdjustMessagePreparator
        extends SshMessagePreparator<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessagePreparator(
            Chooser chooser, ChannelWindowAdjustMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST);
        // TODO dummy values for fuzzing
        getObject().setRecipientChannel(Integer.MAX_VALUE);
        getObject().setBytesToAdd(Integer.MAX_VALUE);
    }
}
