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

    @Override
    public void prepareProtocolMessageContents(AsciiMessage object, Chooser chooser) {
        object.setText(""); // TODO: Add a way to set this via configuration.
        if (chooser.getContext().isClient()) {
            object.setEndOfMessageSequence(chooser.getClientEndOfMessageSequence());
        } else {
            object.setEndOfMessageSequence(chooser.getServerEndOfMessageSequence());
        }
    }
}
