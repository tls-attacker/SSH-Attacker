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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenDirectStreamlocalOpenSshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ChannelOpenDirectStreamlocalOpenSshMessage
        extends ChannelOpenMessage<ChannelOpenDirectStreamlocalOpenSshMessage> {

    private ModifiableInteger socketPathLength;
    private ModifiableString socketPath;
    private ModifiableInteger reservedStringLength;
    private ModifiableByteArray reservedString;
    private ModifiableInteger reservedUint32;

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

    public ModifiableInteger getReservedStringLength() {
        return reservedStringLength;
    }

    public void setReservedStringLength(ModifiableInteger reservedStringLength) {
        this.reservedStringLength = reservedStringLength;
    }

    public void setReservedStringLength(int reservedStringLength) {
        this.reservedStringLength =
                ModifiableVariableFactory.safelySetValue(
                        this.reservedStringLength, reservedStringLength);
    }

    public ModifiableByteArray getReservedString() {
        return reservedString;
    }

    public void setReservedString(ModifiableByteArray reservedString) {
        setReservedString(reservedString, false);
    }

    public void setReservedString(byte[] reservedString) {
        setReservedString(reservedString, false);
    }

    public void setReservedString(ModifiableByteArray reservedString, boolean adjustLengthField) {
        this.reservedString = reservedString;
        if (adjustLengthField) {
            setReservedStringLength(reservedString.getValue().length);
        }
    }

    public void setReservedString(byte[] reservedString, boolean adjustLengthField) {
        this.reservedString =
                ModifiableVariableFactory.safelySetValue(this.reservedString, reservedString);
        if (adjustLengthField) {
            setReservedStringLength(reservedString.length);
        }
    }

    public ModifiableInteger getReservedUint32() {
        return reservedUint32;
    }

    public void setReservedUint32(ModifiableInteger reservedUint32) {
        this.reservedUint32 = reservedUint32;
    }

    public void setReservedUint32(int reservedUint32) {
        this.reservedUint32 =
                ModifiableVariableFactory.safelySetValue(this.reservedUint32, reservedUint32);
    }

    @Override
    public ChannelOpenDirectStreamlocalOpenSshMessageHandler getHandler(SshContext context) {
        return new ChannelOpenDirectStreamlocalOpenSshMessageHandler(context, this);
    }
}
