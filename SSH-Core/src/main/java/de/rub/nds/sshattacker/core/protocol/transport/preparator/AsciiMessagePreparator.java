/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class AsciiMessagePreparator extends ProtocolMessagePreparator<AsciiMessage> {
    public AsciiMessagePreparator(Chooser chooser, AsciiMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareProtocolMessageContents() {
        getObject().setText(""); // TODO: Add a way to set this via configuration.
        if (chooser.getContext().isClient()) {
            getObject().setEndOfMessageSequence(chooser.getClientEndOfMessageSequence());
        } else {
            getObject().setEndOfMessageSequence(chooser.getServerEndOfMessageSequence());
        }
    }
}
