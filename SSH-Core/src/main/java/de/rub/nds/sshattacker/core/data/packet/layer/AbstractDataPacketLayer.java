/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.layer;

import de.rub.nds.sshattacker.core.data.packet.AbstractDataPacket;
import de.rub.nds.sshattacker.core.data.packet.serializer.AbstractDataPacketSerializer;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.state.SshContext;

/**
 * An abstraction layer that can be used to define different packet layer types that can occur in
 * channel data.
 */
public abstract class AbstractDataPacketLayer {

    protected final SshContext context;

    protected AbstractDataPacketLayer(SshContext context) {
        super();
        this.context = context;
    }

    /**
     * Tries to parse a single packet from rawBytes at startPosition. If this is not possible a
     * Parser Exception is thrown.
     *
     * @param rawBytes Bytes to parse
     * @param startPosition Start position for parsing
     * @return The parsed packet
     * @throws ParserException Thrown whenever parsing the provided bytes fails
     */
    public abstract DataPacketLayerParseResult parsePacket(byte[] rawBytes, int startPosition)
            throws ParserException;

    /**
     * Tries to parse a single packet from rawBytes at startPosition. Exception which might occur
     * are handled.
     *
     * @param rawBytes Bytes to parse
     * @param startPosition Start position for parsing
     * @return The parsed packet
     */
    public abstract DataPacketLayerParseResult parsePacketSoftly(
            byte[] rawBytes, int startPosition);

    public byte[] preparePacket(AbstractDataPacket packet) {
        packet.prepare(context.getChooser());
        AbstractDataPacketSerializer<? extends AbstractDataPacket> serializer =
                packet.getPacketSerializer();
        return serializer.serialize();
    }
}
