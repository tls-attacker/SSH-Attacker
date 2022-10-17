/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestSubsystemMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestSubsystemMessage> {

    public ChannelRequestSubsystemMessagePreparator(
            Chooser chooser, ChannelRequestSubsystemMessage message) {
        super(chooser, message, ChannelRequestType.SUBSYSTEM);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents() {
        getObject().setSubsystemName(chooser.getConfig().getDefaultSubsystemName(), true);
    }
}
