package de.rub.nds.sshattacker.core.packet.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Handler;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;

public abstract class AbstractPacketHandler<AbstractT extends AbstractPacket> implements Handler<AbstractT> {

    protected  SshContext sshContext = null;

    public AbstractPacketHandler(SshContext sshContext) {
        this.sshContext = sshContext;
    }
}
