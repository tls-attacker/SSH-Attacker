/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.constants.SignalType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitSignalMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestExitSignalMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestExitSignalMessage> {

    public ChannelRequestExitSignalMessagePreparator(
            Chooser chooser, ChannelRequestExitSignalMessage message) {
        super(chooser, message, ChannelRequestType.EXIT_SIGNAL);
    }

    @Override
    public void prepareChannelRequestMessageSpecificContents() {
        getObject().setSoftlySignalName(SignalType.SIGINT, true, chooser.getConfig());
        getObject().setSoftlyCoreDump(false);
        getObject().setSoftlyErrorMessage("", true, chooser.getConfig());
        getObject().setSoftlyLanguageTag("", true, chooser.getConfig());
    }
}
