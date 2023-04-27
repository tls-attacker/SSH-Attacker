/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Preparator<T> {

    private final T object;
    protected final Chooser chooser;

    private static final Logger LOGGER = LogManager.getLogger();

    public Preparator(Chooser chooser, T message) {
        this.object = message;
        this.chooser = chooser;
        if (object == null) {
            throw new PreparationException("Cannot prepare NULL");
        }
    }

    public abstract void prepare();

    public T getObject() {
        return object;
    }
}
