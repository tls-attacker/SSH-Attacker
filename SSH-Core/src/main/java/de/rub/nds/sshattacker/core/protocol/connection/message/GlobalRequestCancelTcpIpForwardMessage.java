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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestCancelTcpIpForwardMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class GlobalRequestCancelTcpIpForwardMessage
        extends GlobalRequestMessage<GlobalRequestCancelTcpIpForwardMessage> {

    private ModifiableInteger ipAddressToBindLength;
    private ModifiableString ipAddressToBind;
    private ModifiableInteger portToBind;

    public GlobalRequestCancelTcpIpForwardMessage() {
        super();
    }

    public GlobalRequestCancelTcpIpForwardMessage(GlobalRequestCancelTcpIpForwardMessage other) {
        super(other);
        ipAddressToBindLength =
                other.ipAddressToBindLength != null
                        ? other.ipAddressToBindLength.createCopy()
                        : null;
        ipAddressToBind = other.ipAddressToBind != null ? other.ipAddressToBind.createCopy() : null;
        portToBind = other.portToBind != null ? other.portToBind.createCopy() : null;
    }

    @Override
    public GlobalRequestCancelTcpIpForwardMessage createCopy() {
        return new GlobalRequestCancelTcpIpForwardMessage(this);
    }

    public ModifiableString getIpAddressToBind() {
        return ipAddressToBind;
    }

    public void setIpAddressToBind(ModifiableString ipAddressToBind) {
        this.ipAddressToBind = ipAddressToBind;
    }

    public void setIpAddressToBind(String ipAddressToBind) {
        this.ipAddressToBind =
                ModifiableVariableFactory.safelySetValue(this.ipAddressToBind, ipAddressToBind);
    }

    public void setIpAddressToBind(ModifiableString ipAddressToBind, boolean adjustLengthField) {
        this.ipAddressToBind = ipAddressToBind;
        if (adjustLengthField) {
            setIpAddressToBindLength(
                    this.ipAddressToBind.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setIpAddressToBind(String ipAddressToBind, boolean adjustLengthField) {
        this.ipAddressToBind =
                ModifiableVariableFactory.safelySetValue(this.ipAddressToBind, ipAddressToBind);
        if (adjustLengthField) {
            setIpAddressToBindLength(
                    this.ipAddressToBind.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public ModifiableInteger getIpAddressToBindLength() {
        return ipAddressToBindLength;
    }

    public void setIpAddressToBindLength(ModifiableInteger ipAddressToBindLength) {
        this.ipAddressToBindLength = ipAddressToBindLength;
    }

    public void setIpAddressToBindLength(int ipAddressToBindLength) {
        this.ipAddressToBindLength =
                ModifiableVariableFactory.safelySetValue(
                        this.ipAddressToBindLength, ipAddressToBindLength);
    }

    public ModifiableInteger getPortToBind() {
        return portToBind;
    }

    public void setPortToBind(ModifiableInteger portToBind) {
        this.portToBind = portToBind;
    }

    public void setPortToBind(int portToBind) {
        this.portToBind = ModifiableVariableFactory.safelySetValue(this.portToBind, portToBind);
    }

    public static final GlobalRequestCancelTcpIpForwardMessageHandler HANDLER =
            new GlobalRequestCancelTcpIpForwardMessageHandler();

    @Override
    public GlobalRequestCancelTcpIpForwardMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        GlobalRequestCancelTcpIpForwardMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return GlobalRequestCancelTcpIpForwardMessageHandler.SERIALIZER.serialize(this);
    }
}
