package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.state.SshContext;

public abstract class Handler<T> {
    
    protected final SshContext context;
    protected final T message;

    public Handler(SshContext context, T message) {
        this.message = message;
        this.context = context;
    }
    
    public abstract void handle();
}
