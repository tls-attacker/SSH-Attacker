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

    protected SftpMessagePreparator(SftpPacketTypeConstant packetType) {
        this(packetType.getId());
    }

    protected SftpMessagePreparator(byte packetType) {
        super();
        this.packetType = packetType;
    }

    @Override
    public final void prepareProtocolMessageContents(T object, Chooser chooser) {
        // Always set correct packet type -> Don't use soft set
        object.setPacketType(packetType);
        prepareMessageSpecificContents(object, chooser);
    }

    protected abstract void prepareMessageSpecificContents(T object, Chooser chooser);
}
