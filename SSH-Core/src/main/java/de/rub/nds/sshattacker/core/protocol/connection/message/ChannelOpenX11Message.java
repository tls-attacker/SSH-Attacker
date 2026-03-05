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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenX11MessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class ChannelOpenX11Message extends ChannelOpenMessage<ChannelOpenX11Message> {

    private ModifiableInteger originatorAddressLength;
    private ModifiableString originatorAddress;
    private ModifiableInteger originatorPort;

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

    public ChannelOpenX11Message() {
        super();
    }

    public ChannelOpenX11Message(ChannelOpenX11Message other) {
        super(other);
        originatorAddressLength =
                other.originatorAddressLength != null
                        ? other.originatorAddressLength.createCopy()
                        : null;
        originatorAddress =
                other.originatorAddress != null ? other.originatorAddress.createCopy() : null;
        originatorPort = other.originatorPort != null ? other.originatorPort.createCopy() : null;
    }

    @Override
    public ChannelOpenX11Message createCopy() {
        return new ChannelOpenX11Message(this);
    }

    public static final ChannelOpenX11MessageHandler HANDLER = new ChannelOpenX11MessageHandler();

    @Override
    public ChannelOpenX11MessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelOpenX11MessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelOpenX11MessageHandler.SERIALIZER.serialize(this);
    }
}
