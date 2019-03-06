package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.state.SshContext;
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
