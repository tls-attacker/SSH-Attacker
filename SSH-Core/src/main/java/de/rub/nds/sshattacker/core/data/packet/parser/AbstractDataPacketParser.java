/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.parser;

import de.rub.nds.sshattacker.core.data.packet.AbstractDataPacket;
import de.rub.nds.sshattacker.core.protocol.common.Parser;

public abstract class AbstractDataPacketParser<T extends AbstractDataPacket> extends Parser<T> {

    protected AbstractDataPacketParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }
}
