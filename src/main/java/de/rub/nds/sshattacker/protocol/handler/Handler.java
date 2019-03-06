package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.state.SshContext;

public abstract class Handler<T> {

    protected final SshContext context;

    public Handler(SshContext context) {
        this.context = context;
    }

    public abstract void handle(T msg);
}
