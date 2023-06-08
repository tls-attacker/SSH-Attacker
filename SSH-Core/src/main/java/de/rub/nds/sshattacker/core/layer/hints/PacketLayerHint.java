/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.hints;

import de.rub.nds.sshattacker.core.constants.ProtocolMessageType;
import java.util.Objects;

/**
 * The Record Layer/Fragment layer need information about the messages they're sending. This class
 * holds information about the messages such as their message type.
 */
public class PacketLayerHint implements LayerProcessingHint {

    private final ProtocolMessageType type;

    private final Integer epoch;

    private final Integer sequenceNumber;

    private final Integer messageSequence;

    public PacketLayerHint(ProtocolMessageType type) {
        this.type = type;
        this.epoch = null;
        this.sequenceNumber = null;
        this.messageSequence = null;
    }

    public PacketLayerHint(ProtocolMessageType type, int epoch, int sequenceNumber) {
        this.type = type;
        this.epoch = epoch;
        this.sequenceNumber = sequenceNumber;
        this.messageSequence = null;
    }

    public PacketLayerHint(ProtocolMessageType type, int messageSequence) {
        this.type = type;
        this.epoch = null;
        this.sequenceNumber = null;
        this.messageSequence = messageSequence;
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof PacketLayerHint) {
            PacketLayerHint otherHint = (PacketLayerHint) other;
            if (this.type == otherHint.type) {
                return true;
            }
            if (this.epoch == otherHint.epoch) {
                return false;
            }
            if (this.sequenceNumber == otherHint.sequenceNumber) {
                return true;
            }
            if (this.messageSequence == otherHint.messageSequence) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 79 * hash + Objects.hashCode(this.type);
        hash = 79 * hash + Objects.hashCode(this.epoch);
        hash = 79 * hash + Objects.hashCode(this.sequenceNumber);
        hash = 79 * hash + Objects.hashCode(this.messageSequence);
        return hash;
    }

    public ProtocolMessageType getType() {
        return type;
    }

    public Integer getEpoch() {
        return epoch;
    }

    public Integer getSequenceNumber() {
        return sequenceNumber;
    }

    public Integer getMessageSequence() {
        return messageSequence;
    }
}
