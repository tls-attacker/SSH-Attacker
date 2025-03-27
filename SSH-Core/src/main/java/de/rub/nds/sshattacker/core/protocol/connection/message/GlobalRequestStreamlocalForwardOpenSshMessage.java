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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestStreamlocalForwardOpenSshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class GlobalRequestStreamlocalForwardOpenSshMessage
        extends GlobalRequestMessage<GlobalRequestStreamlocalForwardOpenSshMessage> {

    private ModifiableInteger socketPathLength;
    private ModifiableString socketPath;

    public ModifiableInteger getSocketPathLength() {
        return socketPathLength;
    }

    public void setSocketPathLength(ModifiableInteger socketPathLength) {
        this.socketPathLength = socketPathLength;
    }

    public void setSocketPathLength(int socketPathLength) {
        this.socketPathLength =
                ModifiableVariableFactory.safelySetValue(this.socketPathLength, socketPathLength);
    }

    public ModifiableString getSocketPath() {
        return socketPath;
    }

    public void setSocketPath(ModifiableString socketPath) {
        setSocketPath(socketPath, false);
    }

    public void setSocketPath(String socketPath) {
        setSocketPath(socketPath, false);
    }

    public void setSocketPath(String socketPath, boolean adjustLengthField) {
        this.socketPath = ModifiableVariableFactory.safelySetValue(this.socketPath, socketPath);
        if (adjustLengthField) {
            setSocketPathLength(socketPath.getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSocketPath(ModifiableString socketPath, boolean adjustLengthField) {
        this.socketPath = socketPath;
        if (adjustLengthField) {
            setSocketPathLength(socketPath.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    @Override
    public GlobalRequestStreamlocalForwardOpenSshMessageHandler getHandler(SshContext context) {
        return new GlobalRequestStreamlocalForwardOpenSshMessageHandler(context, this);
    }
}
