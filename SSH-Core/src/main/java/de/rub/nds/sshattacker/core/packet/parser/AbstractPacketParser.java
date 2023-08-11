/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.parser;

import de.rub.nds.sshattacker.core.layer.data.Parser;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import java.io.InputStream;

public abstract class AbstractPacketParser<T extends AbstractPacket<?>> extends Parser<T> {

    public AbstractPacketParser(InputStream stream) {
        super(stream);
    }
}
