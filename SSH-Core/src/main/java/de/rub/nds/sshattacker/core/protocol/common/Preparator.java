/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class Preparator<T> {

    protected final T object;
    protected final Chooser chooser;
    protected final Config config;

    protected Preparator(Chooser chooser, T message) {
        super();
        object = message;
        this.chooser = chooser;
        config = chooser.getConfig();
        if (object == null) {
            throw new PreparationException("Cannot prepare NULL");
        }
    }

    // TODO: I think the preperator concept could be made with a static instance for each message
    //  type, and a prepare method that accepts a message object that should be prepared and a
    //  context (chooser), or even just be part of each message
    public abstract void prepare();

    public T getObject() {
        return object;
    }
}
