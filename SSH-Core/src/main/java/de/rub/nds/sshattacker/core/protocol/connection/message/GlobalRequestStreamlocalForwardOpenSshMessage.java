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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class GlobalRequestStreamlocalForwardOpenSshMessage
        extends GlobalRequestMessage<GlobalRequestStreamlocalForwardOpenSshMessage> {

    private ModifiableInteger socketPathLength;
    private ModifiableString socketPath;

    public GlobalRequestStreamlocalForwardOpenSshMessage() {
        super();
    }

    public GlobalRequestStreamlocalForwardOpenSshMessage(
            GlobalRequestStreamlocalForwardOpenSshMessage other) {
        super(other);
        socketPathLength =
                other.socketPathLength != null ? other.socketPathLength.createCopy() : null;
        socketPath = other.socketPath != null ? other.socketPath.createCopy() : null;
    }

    @Override
    public GlobalRequestStreamlocalForwardOpenSshMessage createCopy() {
        return new GlobalRequestStreamlocalForwardOpenSshMessage(this);
    }

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

    public static final GlobalRequestStreamlocalForwardOpenSshMessageHandler HANDLER =
            new GlobalRequestStreamlocalForwardOpenSshMessageHandler();

    @Override
    public GlobalRequestStreamlocalForwardOpenSshMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        GlobalRequestStreamlocalForwardOpenSshMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return GlobalRequestStreamlocalForwardOpenSshMessageHandler.SERIALIZER.serialize(this);
    }
}
