/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Preparator<T> {

    protected final T message;
    protected final SshContext context;

    private static final Logger LOGGER = LogManager.getLogger();

    public Preparator(SshContext context, T message) {
        this.message = message;
        this.context = context;
    }

    public abstract void prepare();

    public T getMessage() {
        return message;
    }
}
