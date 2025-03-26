/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenSessionMessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenSessionMessage> {
    public ChannelOpenSessionMessagePreparator(Chooser chooser, ChannelOpenSessionMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents() {}
}
