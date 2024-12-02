/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator.holder;

import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class AuthenticationResponseEntryPreparator extends Preparator<AuthenticationResponseEntry> {

    public AuthenticationResponseEntryPreparator(
            Chooser chooser, AuthenticationResponseEntry authenticationResponseEntry) {
        super(chooser, authenticationResponseEntry);
    }

    @Override
    public final void prepare() {
        getObject().setResponse("6d757575", true);
    }
}
