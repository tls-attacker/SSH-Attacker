package de.rub.nds.sshattacker.core.packet.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;

public class BinaryPacketHandler extends AbstractPacketHandler<BinaryPacket>{


    public BinaryPacketHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(BinaryPacket object) {

    }
}
