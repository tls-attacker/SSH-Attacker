/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelDataMessagePreparator extends ChannelMessagePreparator<ChannelDataMessage> {

    public ChannelDataMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_CHANNEL_DATA);
    }

    @Override
    public void prepareChannelMessageSpecificContents(ChannelDataMessage object, Chooser chooser) {
        // TODO dummy values for fuzzing
        object.setData(new byte[100], true);
    }
}
