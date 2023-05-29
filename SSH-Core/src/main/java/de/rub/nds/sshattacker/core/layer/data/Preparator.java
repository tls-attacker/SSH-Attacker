/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.data;

import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T> The Object that should be prepared
 */
public abstract class Preparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Chooser chooser;
    private final T object;

    public Preparator(Chooser chooser, T object) {
        this.chooser = chooser;
        this.object = object;
        if (object == null) {
            throw new PreparationException("Cannot prepare NULL");
        }
    }

    public abstract void prepare();

    /**
     * If clientMode is active, the prepareAfterParse method will compute all the values as though
     * the client parsed this Method. This is mostly only useful if you are reparsing or doing
     * something really crazy. For any normal use case this should be set to false;
     *
     * @param clientMode
     */
    public void prepareAfterParse(boolean clientMode) {}

    public T getObject() {
        return object;
    }

    public void afterPrepare() {}
}
