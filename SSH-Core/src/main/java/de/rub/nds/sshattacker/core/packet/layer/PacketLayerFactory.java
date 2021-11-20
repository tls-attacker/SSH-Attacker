/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.layer;

import de.rub.nds.sshattacker.core.constants.PacketLayerType;
import de.rub.nds.sshattacker.core.state.SshContext;

public class PacketLayerFactory {

    public static AbstractPacketLayer getPacketLayer(PacketLayerType type, SshContext context) {
        switch (type) {
            case BINARY_PACKET:
                return new BinaryPacketLayer(context);
            case BLOB:
                return new BlobPacketLayer(context);
            default:
                throw new UnsupportedOperationException(
                        "Packet layer type '" + type + "' not supported!");
        }
    }

    private PacketLayerFactory() {}
}
