/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelWindowAdjustMessagePreparator
        extends ChannelMessagePreparator<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST);
    }

    @Override
    public void prepareChannelMessageSpecificContents(
            ChannelWindowAdjustMessage object, Chooser chooser) {
        object.setSoftlyRecipientChannelId(
                channel.getRemoteChannelId().getValue(), chooser.getConfig());
        object.setSoftlyBytesToAdd(
                chooser.getConfig().getChannelDefaults().getLocalWindowSize()
                        - channel.getLocalWindowSize().getValue());
    }
}
