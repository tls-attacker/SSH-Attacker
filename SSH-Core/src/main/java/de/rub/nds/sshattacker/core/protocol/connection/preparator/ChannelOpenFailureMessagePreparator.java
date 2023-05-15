/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenFailureMessagePreparator
        extends ChannelMessagePreparator<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessagePreparator(Chooser chooser, ChannelOpenFailureMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_OPEN_FAILURE);
    }

    @Override
    public void prepareChannelMessageSpecificContents() {
        // TODO dummy values for fuzzing
        getObject().setReasonCode(Integer.MAX_VALUE);
        getObject().setReason("", true);
        getObject().setLanguageTag("", true);
    }
}
