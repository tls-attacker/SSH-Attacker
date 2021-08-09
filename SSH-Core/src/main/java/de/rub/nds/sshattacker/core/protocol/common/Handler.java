/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Handler<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final SshContext context;

    public Handler(SshContext context) {
        this.context = context;
    }

    public abstract void handle(T msg);

    protected void raiseAdjustmentException(String errorMsg) {
        if (context.getConfig().getAvoidAdjustmentExceptions()) {
            LOGGER.warn(errorMsg);
        } else {
            throw new AdjustmentException(errorMsg);
        }
    }
}
