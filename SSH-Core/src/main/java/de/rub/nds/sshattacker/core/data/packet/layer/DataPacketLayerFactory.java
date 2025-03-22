/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.layer;

import de.rub.nds.sshattacker.core.constants.DataPacketLayerType;
import de.rub.nds.sshattacker.core.state.SshContext;

public final class DataPacketLayerFactory {

    public static AbstractDataPacketLayer getDataPacketLayer(
            DataPacketLayerType type, SshContext context) {
        return switch (type) {
            case DATA -> DataPacketLayer.INSTANCE;
            case PASS_THROUGH -> PassThroughPacketLayer.INSTANCE;
        };
    }

    private DataPacketLayerFactory() {
        super();
    }
}
