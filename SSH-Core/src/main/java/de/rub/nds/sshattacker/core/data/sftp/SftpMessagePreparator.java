/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SftpMessagePreparator<T extends SftpMessage<T>>
        extends ProtocolMessagePreparator<T> {

    private final Byte packetType;

    protected SftpMessagePreparator(Chooser chooser, T message, SftpPacketTypeConstant packetType) {
        this(chooser, message, packetType.getId());
    }

    protected SftpMessagePreparator(Chooser chooser, T message, byte packetType) {
        super(chooser, message);
        this.packetType = packetType;
    }

    @Override
    public final void prepareProtocolMessageContents() {
        // Always set correct packet type -> Don't use soft set
        getObject().setPacketType(packetType);
        prepareMessageSpecificContents();
    }

    protected abstract void prepareMessageSpecificContents();
}
