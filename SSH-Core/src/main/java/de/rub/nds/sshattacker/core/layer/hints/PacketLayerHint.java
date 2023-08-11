/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.hints;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import java.util.Objects;

/**
 * The Record Layer/Fragment layer need information about the messages they're sending. This class
 * holds information about the messages such as their message type.
 */
public class PacketLayerHint implements LayerProcessingHint {

    private final MessageIdConstant type;

    private final Integer sequenceNumber;

    public PacketLayerHint(MessageIdConstant type) {
        this.type = type;
        this.sequenceNumber = null;
    }

    public PacketLayerHint(MessageIdConstant type, int epoch, int sequenceNumber) {
        this.type = type;
        this.sequenceNumber = sequenceNumber;
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof PacketLayerHint) {
            PacketLayerHint otherHint = (PacketLayerHint) other;
            if (this.type == otherHint.type) {
                return true;
            }
            if (this.sequenceNumber == otherHint.sequenceNumber) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 79 * hash + Objects.hashCode(this.type);
        hash = 79 * hash + Objects.hashCode(this.sequenceNumber);
        return hash;
    }

    public MessageIdConstant getType() {
        return type;
    }

    public Integer getSequenceNumber() {
        return sequenceNumber;
    }
}
