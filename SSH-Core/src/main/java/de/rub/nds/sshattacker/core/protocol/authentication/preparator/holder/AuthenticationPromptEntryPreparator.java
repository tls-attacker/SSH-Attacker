/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator.holder;

import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class AuthenticationPromptEntryPreparator extends Preparator<AuthenticationPromptEntry> {

    public AuthenticationPromptEntryPreparator(
            Chooser chooser, AuthenticationPromptEntry authenticationPromptEntry) {
        super(chooser, authenticationPromptEntry);
    }

    @Override
    public final void prepare() {
        getObject().setPrompt("Response: ");
        getObject().setEcho(true);
    }
}
