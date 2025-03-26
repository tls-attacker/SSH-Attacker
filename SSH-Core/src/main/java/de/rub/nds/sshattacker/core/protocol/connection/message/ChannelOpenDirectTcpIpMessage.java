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
        this.hostToConnect = hostToConnect;
    }

    public void setHostToConnect(String hostToConnect) {
        this.hostToConnect =
                ModifiableVariableFactory.safelySetValue(this.hostToConnect, hostToConnect);
    }

    public void setHostToConnect(ModifiableString hostToConnect, boolean adjustLengthField) {
        this.hostToConnect = hostToConnect;
        if (adjustLengthField) {
            setHostToConnectLength(this.hostToConnect.getValue().getBytes().length);
        }
    }

    public void setHostToConnect(String hostToConnect, boolean adjustLengthField) {
        this.hostToConnect =
                ModifiableVariableFactory.safelySetValue(this.hostToConnect, hostToConnect);
        if (adjustLengthField) {
            setHostToConnectLength(this.hostToConnect.getValue().getBytes().length);
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
        this.originatorAddress = originatorAddress;
    }

    public void setOriginatorAddress(String originatorAddress) {
        this.originatorAddress =
                ModifiableVariableFactory.safelySetValue(this.originatorAddress, originatorAddress);
    }

    public void setOriginatorAddress(
            ModifiableString originatorAddress, boolean adjustLengthField) {
        this.originatorAddress = originatorAddress;
        if (adjustLengthField) {
            setOriginatorAddressLength(this.originatorAddress.getValue().getBytes().length);
        }
    }

    public void setOriginatorAddress(String originatorAddress, boolean adjustLengthField) {
        this.originatorAddress =
                ModifiableVariableFactory.safelySetValue(this.originatorAddress, originatorAddress);
        if (adjustLengthField) {
            setOriginatorAddressLength(this.originatorAddress.getValue().getBytes().length);
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

    @Override
    public ChannelOpenDirectTcpIpMessageHandler getHandler(SshContext context) {
        return new ChannelOpenDirectTcpIpMessageHandler(context, this);
    }
}
