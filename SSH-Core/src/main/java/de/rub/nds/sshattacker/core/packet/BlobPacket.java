/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Handler;
import de.rub.nds.sshattacker.core.packet.parser.BlobPacketParser;
import de.rub.nds.sshattacker.core.packet.preparator.BlobPacketPreparator;
import de.rub.nds.sshattacker.core.packet.serializer.BlobPacketSerializer;
import java.io.InputStream;

public class BlobPacket extends AbstractPacket<BlobPacket> {

    @Override
    public void prepareComputations() {}

    @Override
    public BlobPacketParser getParser(SshContext context, InputStream stream) {
        return new BlobPacketParser(stream);
    }

    @Override
    public BlobPacketPreparator getPreparator(SshContext context) {
        return new BlobPacketPreparator(
                context.getChooser(), this, context.getEncryptor(), context.getCompressor());
    }

    @Override
    public BlobPacketSerializer getSerializer(SshContext context) {
        return new BlobPacketSerializer(this);
    }

    @Override
    public Handler<BlobPacket> getHandler(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
