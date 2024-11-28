/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestExitStatusMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestExitStatusMessage
        extends ChannelRequestMessage<ChannelRequestExitStatusMessage> {

    private ModifiableInteger exitStatus;

    public ModifiableInteger getExitStatus() {
        return exitStatus;
    }

    public void setExitStatus(ModifiableInteger exitStatus) {
        this.exitStatus = exitStatus;
    }

    public void setExitStatus(int exitStatus) {
        this.exitStatus = ModifiableVariableFactory.safelySetValue(this.exitStatus, exitStatus);
    }

    public void setSoftlyExitStatus(int exitStatus) {
        if (this.exitStatus == null || this.exitStatus.getOriginalValue() == null) {
            this.exitStatus = ModifiableVariableFactory.safelySetValue(this.exitStatus, exitStatus);
        }
    }

    @Override
    public ChannelRequestExitStatusMessageHandler getHandler(SshContext context) {
        return new ChannelRequestExitStatusMessageHandler(context, this);
    }
}
