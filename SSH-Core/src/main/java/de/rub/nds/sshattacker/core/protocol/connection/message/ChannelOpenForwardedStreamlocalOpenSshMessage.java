/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenForwardedStreamlocalOpenSshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ChannelOpenForwardedStreamlocalOpenSshMessage
        extends ChannelOpenMessage<ChannelOpenForwardedStreamlocalOpenSshMessage> {

    private ModifiableInteger socketPathLength;
    private ModifiableString socketPath;
    private ModifiableInteger reservedLength;
    private ModifiableByteArray reserved;

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

    public ModifiableInteger getReservedLength() {
        return reservedLength;
    }

    public void setReservedLength(ModifiableInteger reservedLength) {
        this.reservedLength = reservedLength;
    }

    public void setReservedLength(int reservedLength) {
        this.reservedLength =
                ModifiableVariableFactory.safelySetValue(this.reservedLength, reservedLength);
    }

    public ModifiableByteArray getReserved() {
        return reserved;
    }

    public void setReserved(ModifiableByteArray reserved) {
        setReserved(reserved, false);
    }

    public void setReserved(byte[] reserved) {
        setReserved(reserved, false);
    }

    public void setReserved(ModifiableByteArray reserved, boolean adjustLengthField) {
        this.reserved = reserved;
        if (adjustLengthField) {
            setReservedLength(reserved.getValue().length);
        }
    }

    public void setReserved(byte[] reserved, boolean adjustLengthField) {
        this.reserved = ModifiableVariableFactory.safelySetValue(this.reserved, reserved);
        if (adjustLengthField) {
            setReservedLength(reserved.length);
        }
    }

    @Override
    public ChannelOpenForwardedStreamlocalOpenSshMessageHandler getHandler(SshContext context) {
        return new ChannelOpenForwardedStreamlocalOpenSshMessageHandler(context, this);
    }
}
