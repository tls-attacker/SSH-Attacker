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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenDirectTcpIpMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class ChannelOpenDirectTcpIpMessage
        extends ChannelOpenMessage<ChannelOpenDirectTcpIpMessage> {

    private ModifiableInteger hostToConnectLength;
    private ModifiableString hostToConnect;
    private ModifiableInteger portToConnect;
    private ModifiableInteger originatorAddressLength;
    private ModifiableString originatorAddress;
    private ModifiableInteger originatorPort;

    public ModifiableInteger getHostToConnectLength() {
        return hostToConnectLength;
    }

    public void setHostToConnectLength(ModifiableInteger hostToConnectLength) {
        this.hostToConnectLength = hostToConnectLength;
    }

    public void setHostToConnectLength(int hostToConnectLength) {
        this.hostToConnectLength =
                ModifiableVariableFactory.safelySetValue(
                        this.hostToConnectLength, hostToConnectLength);
    }

    public ModifiableString getHostToConnect() {
        return hostToConnect;
    }

    public void setHostToConnect(ModifiableString hostToConnect) {
        setHostToConnect(hostToConnect, false);
    }

    public void setHostToConnect(String hostToConnect) {
        setHostToConnect(hostToConnect, false);
    }

    public void setHostToConnect(ModifiableString hostToConnect, boolean adjustLengthField) {
        this.hostToConnect = hostToConnect;
        if (adjustLengthField) {
            setHostToConnectLength(
                    this.hostToConnect.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setHostToConnect(String hostToConnect, boolean adjustLengthField) {
        this.hostToConnect =
                ModifiableVariableFactory.safelySetValue(this.hostToConnect, hostToConnect);
        if (adjustLengthField) {
            setHostToConnectLength(
                    this.hostToConnect.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public ModifiableInteger getPortToConnect() {
        return portToConnect;
    }

    public void setPortToConnect(ModifiableInteger portToConnect) {
        this.portToConnect = portToConnect;
    }

    public void setPortToConnect(int portToConnect) {
        this.portToConnect =
                ModifiableVariableFactory.safelySetValue(this.portToConnect, portToConnect);
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

    public ChannelOpenDirectTcpIpMessage() {
        super();
    }

    public ChannelOpenDirectTcpIpMessage(ChannelOpenDirectTcpIpMessage other) {
        super(other);
        hostToConnectLength =
                other.hostToConnectLength != null ? other.hostToConnectLength.createCopy() : null;
        hostToConnect = other.hostToConnect != null ? other.hostToConnect.createCopy() : null;
        portToConnect = other.portToConnect != null ? other.portToConnect.createCopy() : null;
        originatorAddressLength =
                other.originatorAddressLength != null
                        ? other.originatorAddressLength.createCopy()
                        : null;
        originatorAddress =
                other.originatorAddress != null ? other.originatorAddress.createCopy() : null;
        originatorPort = other.originatorPort != null ? other.originatorPort.createCopy() : null;
    }

    @Override
    public ChannelOpenDirectTcpIpMessage createCopy() {
        return new ChannelOpenDirectTcpIpMessage(this);
    }

    public static final ChannelOpenDirectTcpIpMessageHandler HANDLER =
            new ChannelOpenDirectTcpIpMessageHandler();

    @Override
    public ChannelOpenDirectTcpIpMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelOpenDirectTcpIpMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelOpenDirectTcpIpMessageHandler.SERIALIZER.serialize(this);
    }
}
