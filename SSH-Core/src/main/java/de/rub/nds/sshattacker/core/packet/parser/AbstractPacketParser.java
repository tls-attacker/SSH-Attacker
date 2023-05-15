/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.parser;

import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.protocol.common.Parser;

public abstract class AbstractPacketParser<T extends AbstractPacket> extends Parser<T> {

    protected AbstractPacketParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }
}
