/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.serializer;

import de.rub.nds.sshattacker.core.data.packet.AbstractDataPacket;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;

public abstract class AbstractDataPacketSerializer<T extends AbstractDataPacket>
        extends Serializer<T> {}
