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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSignalMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestSignalMessagePreparator
        extends ChannelRequestMessagePreparator<ChannelRequestSignalMessage> {

    public ChannelRequestSignalMessagePreparator() {
        super(ChannelRequestType.SIGNAL, false);
    }

    @Override
    protected void prepareChannelRequestMessageSpecificContents(
            ChannelRequestSignalMessage object, Chooser chooser) {
        object.setSignalName(SignalType.SIGINT, true);
    }
}
