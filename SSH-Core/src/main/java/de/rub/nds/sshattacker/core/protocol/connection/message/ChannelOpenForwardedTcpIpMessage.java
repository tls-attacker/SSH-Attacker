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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenForwardedTcpIpMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class ChannelOpenForwardedTcpIpMessage
        extends ChannelOpenMessage<ChannelOpenForwardedTcpIpMessage> {

    private ModifiableInteger connectedAddressLength;
    private ModifiableString connectedAddress;
    private ModifiableInteger connectedPort;
    private ModifiableInteger originatorAddressLength;
    private ModifiableString originatorAddress;
    private ModifiableInteger originatorPort;

    public ModifiableInteger getConnectedAddressLength() {
        return connectedAddressLength;
    }

    public void setConnectedAddressLength(ModifiableInteger connectedAddressLength) {
        this.connectedAddressLength = connectedAddressLength;
    }

    public void setConnectedAddressLength(int connectedAddressLength) {
        this.connectedAddressLength =
                ModifiableVariableFactory.safelySetValue(
                        this.connectedAddressLength, connectedAddressLength);
    }

    public ModifiableString getConnectedAddress() {
        return connectedAddress;
    }

    public void setConnectedAddress(ModifiableString connectedAddress) {
        setConnectedAddress(connectedAddress, false);
    }

    public void setConnectedAddress(String connectedAddress) {
        setConnectedAddress(connectedAddress, false);
    }

    public void setConnectedAddress(ModifiableString connectedAddress, boolean adjustLengthField) {
        this.connectedAddress = connectedAddress;
        if (adjustLengthField) {
            setConnectedAddressLength(
                    this.connectedAddress.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setConnectedAddress(String connectedAddress, boolean adjustLengthField) {
        this.connectedAddress =
                ModifiableVariableFactory.safelySetValue(this.connectedAddress, connectedAddress);
        if (adjustLengthField) {
            setConnectedAddressLength(
                    this.connectedAddress.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public ModifiableInteger getConnectedPort() {
        return connectedPort;
    }

    public void setConnectedPort(ModifiableInteger connectedPort) {
        this.connectedPort = connectedPort;
    }

    public void setConnectedPort(int connectedPort) {
        this.connectedPort =
                ModifiableVariableFactory.safelySetValue(this.connectedPort, connectedPort);
    }

    public ModifiableInteger getOriginatorAddressLength() {
        return originatorAddressLength;
    }

    public void setOriginatorAddressLength(ModifiableInteger originatorAddressLength) {
        this.originatorAddressLength = originatorAddressLength;
    }

    public void setOriginatorAddressLength(int originatorAddressLength) {
        this.originatorAddressLength =
                ModifiableVariableFactory.safelySetValue(
                        this.originatorAddressLength, originatorAddressLength);
    }

    public ModifiableString getOriginatorAddress() {
        return originatorAddress;
    }

    public void setOriginatorAddress(ModifiableString originatorAddress) {
        setOriginatorAddress(originatorAddress, false);
    }

    public void setOriginatorAddress(String originatorAddress) {
        setOriginatorAddress(originatorAddress, false);
    }

    public void setOriginatorAddress(
            ModifiableString originatorAddress, boolean adjustLengthField) {
        this.originatorAddress = originatorAddress;
        if (adjustLengthField) {
            setOriginatorAddressLength(
                    this.originatorAddress.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setOriginatorAddress(String originatorAddress, boolean adjustLengthField) {
        this.originatorAddress =
                ModifiableVariableFactory.safelySetValue(this.originatorAddress, originatorAddress);
        if (adjustLengthField) {
            setOriginatorAddressLength(
                    this.originatorAddress.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public ModifiableInteger getOriginatorPort() {
        return originatorPort;
    }

    public void setOriginatorPort(ModifiableInteger originatorPort) {
        this.originatorPort = originatorPort;
    }

    public void setOriginatorPort(int originatorPort) {
        this.originatorPort =
                ModifiableVariableFactory.safelySetValue(this.originatorPort, originatorPort);
    }

    public ChannelOpenForwardedTcpIpMessage() {
        super();
    }

    public ChannelOpenForwardedTcpIpMessage(ChannelOpenForwardedTcpIpMessage other) {
        super(other);
        connectedAddressLength =
                other.connectedAddressLength != null
                        ? other.connectedAddressLength.createCopy()
                        : null;
        connectedAddress =
                other.connectedAddress != null ? other.connectedAddress.createCopy() : null;
        connectedPort = other.connectedPort != null ? other.connectedPort.createCopy() : null;
        originatorAddressLength =
                other.originatorAddressLength != null
                        ? other.originatorAddressLength.createCopy()
                        : null;
        originatorAddress =
                other.originatorAddress != null ? other.originatorAddress.createCopy() : null;
        originatorPort = other.originatorPort != null ? other.originatorPort.createCopy() : null;
    }

    @Override
    public ChannelOpenForwardedTcpIpMessage createCopy() {
        return new ChannelOpenForwardedTcpIpMessage(this);
    }

    public static final ChannelOpenForwardedTcpIpMessageHandler HANDLER =
            new ChannelOpenForwardedTcpIpMessageHandler();

    @Override
    public ChannelOpenForwardedTcpIpMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelOpenForwardedTcpIpMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelOpenForwardedTcpIpMessageHandler.SERIALIZER.serialize(this);
    }
}
