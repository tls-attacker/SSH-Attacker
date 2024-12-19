/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.string;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class StringDataMessagePreparator extends ProtocolMessagePreparator<StringDataMessage> {

    public StringDataMessagePreparator(Chooser chooser, StringDataMessage message) {
        super(chooser, message);
    }

    public void prepareProtocolMessageContents() {
        object.setSoftlyData("ls /");
    }
}
