package de.rub.nds.sshattacker.core.packet.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;

public class BlobPacketHandler extends AbstractPacketHandler<BlobPacket>{


    public BlobPacketHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(BlobPacket object) {

    }
}
