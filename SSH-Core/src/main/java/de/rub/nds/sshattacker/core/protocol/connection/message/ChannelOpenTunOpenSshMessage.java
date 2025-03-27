/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.OpenSshTunnelMode;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenTunOpenSshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenTunOpenSshMessage extends ChannelOpenMessage<ChannelOpenTunOpenSshMessage> {

    private ModifiableInteger tunnelMode;
    private ModifiableInteger remoteUnitNumber;

    public ModifiableInteger getTunnelMode() {
        return tunnelMode;
    }

    public void setTunnelMode(ModifiableInteger tunnelMode) {
        this.tunnelMode = tunnelMode;
    }

    public void setTunnelMode(int tunnelMode) {
        this.tunnelMode = ModifiableVariableFactory.safelySetValue(this.tunnelMode, tunnelMode);
    }

    public void setTunnelMode(OpenSshTunnelMode tunnelMode) {
        setTunnelMode(tunnelMode.getValue());
    }

    public ModifiableInteger getRemoteUnitNumber() {
        return remoteUnitNumber;
    }

    public void setRemoteUnitNumber(ModifiableInteger remoteUnitNumber) {
        this.remoteUnitNumber = remoteUnitNumber;
    }

    public void setRemoteUnitNumber(int remoteUnitNumber) {
        this.remoteUnitNumber =
                ModifiableVariableFactory.safelySetValue(this.remoteUnitNumber, remoteUnitNumber);
    }

    @Override
    public ChannelOpenTunOpenSshMessageHandler getHandler(SshContext context) {
        return new ChannelOpenTunOpenSshMessageHandler(context, this);
    }
}
