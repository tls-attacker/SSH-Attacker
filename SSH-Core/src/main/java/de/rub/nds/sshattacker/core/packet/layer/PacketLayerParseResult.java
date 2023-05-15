/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.layer;

import de.rub.nds.sshattacker.core.packet.AbstractPacket;

import java.util.Optional;

public class PacketLayerParseResult {

    private final AbstractPacket parsedPacket;

    private final int parsedByteCount;

    private final boolean softParse;

    public PacketLayerParseResult(AbstractPacket parsedPacket, int parsedByteCount) {
        this(parsedPacket, parsedByteCount, false);
    }

    public PacketLayerParseResult(
            AbstractPacket parsedPacket, int parsedByteCount, boolean softParse) {
        super();
        this.parsedPacket = parsedPacket;
        this.parsedByteCount = parsedByteCount;
        this.softParse = softParse;
    }

    public Optional<AbstractPacket> getParsedPacket() {
        return Optional.ofNullable(parsedPacket);
    }

    public int getParsedByteCount() {
        return parsedByteCount;
    }

    public boolean isSoftParse() {
        return softParse;
    }
}
