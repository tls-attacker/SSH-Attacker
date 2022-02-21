/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SshMessagePreparator<T extends SshMessage<T>>
        extends ProtocolMessagePreparator<T> {

    public SshMessagePreparator(Chooser chooser, T message) {
        super(chooser, message);
    }

    @Override
    protected final void prepareProtocolMessageContents() {
        // The value of the message id is a parameter of the SshMessage constructor
        prepareMessageSpecificContents();
    }

    public abstract void prepareMessageSpecificContents();
}
