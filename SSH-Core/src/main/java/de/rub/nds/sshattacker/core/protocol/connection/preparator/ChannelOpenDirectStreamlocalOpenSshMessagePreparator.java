/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectStreamlocalOpenSshMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenDirectStreamlocalOpenSshMessagePreparator
        extends ChannelOpenMessagePreparator<ChannelOpenDirectStreamlocalOpenSshMessage> {

    public ChannelOpenDirectStreamlocalOpenSshMessagePreparator() {
        super(ChannelType.DIRECT_STREAMLOCAL_OPENSSH_COM);
    }

    @Override
    protected void prepareChannelOpenMessageSpecificContents(
            ChannelOpenDirectStreamlocalOpenSshMessage object, Chooser chooser) {
        // TODO: Replace dummy values
        object.setSocketPath("/var/run/sshattacker.sock", true);
        object.setReservedString(new byte[0], true);
        object.setReservedUint32(0);
    }
}
