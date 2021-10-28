/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeOldRequestMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeOldRequestMessage
        extends SshMessage<DhGexKeyExchangeOldRequestMessage> {

    private ModifiableInteger preferredGroupSize;

    public DhGexKeyExchangeOldRequestMessage() {
        super(MessageIDConstant.SSH_MSG_KEX_DH_GEX_REQUEST_OLD);
    }

    public ModifiableInteger getPreferredGroupSize() {
        return preferredGroupSize;
    }

    public void setPreferredGroupSize(ModifiableInteger preferredGroupSize) {
        this.preferredGroupSize = preferredGroupSize;
    }

    public void setPreferredGroupSize(int preferredGroupSize) {
        this.preferredGroupSize =
                ModifiableVariableFactory.safelySetValue(
                        this.preferredGroupSize, preferredGroupSize);
    }

    @Override
    public DhGexKeyExchangeOldRequestMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeOldRequestMessageHandler(context, this);
    }
}
