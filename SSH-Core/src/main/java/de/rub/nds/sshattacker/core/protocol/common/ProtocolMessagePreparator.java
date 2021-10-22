/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class ProtocolMessagePreparator<T extends ProtocolMessage<T>>
        extends Preparator<T> {

    public ProtocolMessagePreparator(Chooser chooser, T message) {
        super(chooser, message);
    }

    @Override
    public final void prepare() {
        prepareProtocolMessageContents();
    }

    protected abstract void prepareProtocolMessageContents();
}
