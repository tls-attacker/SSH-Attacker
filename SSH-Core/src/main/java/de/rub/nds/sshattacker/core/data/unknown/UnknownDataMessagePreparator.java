/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.unknown;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UnknownDataMessagePreparator extends ProtocolMessagePreparator<UnknownDataMessage> {

    protected void prepareProtocolMessageContents(UnknownDataMessage object, Chooser chooser) {
        object.setPayload(new byte[0]);
    }
}
