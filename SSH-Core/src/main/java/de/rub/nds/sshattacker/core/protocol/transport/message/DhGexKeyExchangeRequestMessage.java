/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeRequestMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeRequestMessage extends SshMessage<DhGexKeyExchangeRequestMessage> {

    public static final MessageIdConstant ID = MessageIdConstant.SSH_MSG_KEX_DH_GEX_REQUEST;

    private ModifiableInteger minimalGroupSize;
    private ModifiableInteger preferredGroupSize;
    private ModifiableInteger maximalGroupSize;

    public ModifiableInteger getMinimalGroupSize() {
        return minimalGroupSize;
    }

    public void setMinimalGroupSize(ModifiableInteger minimalGroupSize) {
        this.minimalGroupSize = minimalGroupSize;
    }

    public void setMinimalGroupSize(int minimalGroupSize) {
        this.minimalGroupSize =
                ModifiableVariableFactory.safelySetValue(this.minimalGroupSize, minimalGroupSize);
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

    public ModifiableInteger getMaximalGroupSize() {
        return maximalGroupSize;
    }

    public void setMaximalGroupSize(ModifiableInteger maximalGroupSize) {
        this.maximalGroupSize = maximalGroupSize;
    }

    public void setMaximalGroupSize(int maximalGroupSize) {
        this.maximalGroupSize =
                ModifiableVariableFactory.safelySetValue(this.maximalGroupSize, maximalGroupSize);
    }

    @Override
    public DhGexKeyExchangeRequestMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeRequestMessageHandler(context, this);
    }
}
