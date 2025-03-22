/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.layer;

import de.rub.nds.sshattacker.core.data.packet.AbstractDataPacket;
import java.util.Optional;

public class DataPacketLayerParseResult {

    private final AbstractDataPacket parsedPacket;

    private final int parsedByteCount;

    private final boolean failedParsing;

    public DataPacketLayerParseResult(AbstractDataPacket parsedPacket, int parsedByteCount) {
        this(parsedPacket, parsedByteCount, false);
    }

    public DataPacketLayerParseResult(
            AbstractDataPacket parsedPacket, int parsedByteCount, boolean failedParsing) {
        super();
        this.parsedPacket = parsedPacket;
        this.parsedByteCount = parsedByteCount;
        this.failedParsing = failedParsing;
    }

    public Optional<AbstractDataPacket> getParsedPacket() {
        return Optional.ofNullable(parsedPacket);
    }

    public int getParsedByteCount() {
        return parsedByteCount;
    }

    public boolean failedParsing() {
        return failedParsing;
    }
}
