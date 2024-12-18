/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestExecMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestExecMessage> {

    public ChannelRequestExecMessagePreparator(Chooser chooser, ChannelRequestExecMessage message) {
        super(chooser, message, ChannelRequestType.EXEC);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents() {
        getObject()
                .setSoftlyCommand(
                        chooser.getConfig().getChannelCommand(), true, chooser.getConfig());
    }
}
