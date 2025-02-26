/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DhGexKeyExchangeOldRequestMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeOldRequestMessage> {

    public DhGexKeyExchangeOldRequestMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_KEX_DH_GEX_REQUEST_OLD);
    }

    @Override
    public void prepareMessageSpecificContents(
            DhGexKeyExchangeOldRequestMessage object, Chooser chooser) {
        Integer preferredDhGroupSize = chooser.getPreferredDhGroupSize();

        object.setPreferredGroupSize(preferredDhGroupSize);

        chooser.getContext()
                .getExchangeHashInputHolder()
                .setDhGexPreferredGroupSize(preferredDhGroupSize);
    }
}
