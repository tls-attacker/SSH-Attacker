/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenConfirmationMessagePreparator extends Preparator<ChannelOpenConfirmationMessage> {

    public ChannelOpenConfirmationMessagePreparator(SshContext context, ChannelOpenConfirmationMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION.id);
        // TODO dummy values for fuzzing

        message.setPacketSize(Integer.MAX_VALUE);
        message.setRecipientChannel(Integer.MAX_VALUE);
        message.setSenderChannel(Integer.MAX_VALUE);
        message.setWindowSize(Integer.MAX_VALUE);
    }

}
