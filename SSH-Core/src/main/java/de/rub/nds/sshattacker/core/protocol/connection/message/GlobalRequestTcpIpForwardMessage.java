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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestTcpIpForwardMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class GlobalRequestTcpIpForwardMessage
        extends GlobalRequestMessage<GlobalRequestTcpIpForwardMessage> {

    private ModifiableInteger ipAddressToBindLength;
    private ModifiableString ipAddressToBind;
    private ModifiableInteger portToBind;

    public GlobalRequestTcpIpForwardMessage() {
        super();
    }

    public GlobalRequestTcpIpForwardMessage(GlobalRequestTcpIpForwardMessage other) {
        super(other);
        ipAddressToBindLength =
                other.ipAddressToBindLength != null
                        ? other.ipAddressToBindLength.createCopy()
                        : null;
        ipAddressToBind = other.ipAddressToBind != null ? other.ipAddressToBind.createCopy() : null;
        portToBind = other.portToBind != null ? other.portToBind.createCopy() : null;
    }

    @Override
    public GlobalRequestTcpIpForwardMessage createCopy() {
        return new GlobalRequestTcpIpForwardMessage(this);
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

    public void setSoftlyIpAddressToBind(
            String ipAddressToBind, boolean adjustLengthField, Config config) {
        this.ipAddressToBind =
                ModifiableVariableFactory.softlySetValue(this.ipAddressToBind, ipAddressToBind);
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || ipAddressToBindLength == null
                    || ipAddressToBindLength.getOriginalValue() == null) {
                setIpAddressToBindLength(
                        this.ipAddressToBind.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
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

    public void setSoftlyPortToBind(int portToBind) {
        this.portToBind = ModifiableVariableFactory.softlySetValue(this.portToBind, portToBind);
    }

    public static final GlobalRequestTcpIpForwardMessageHandler HANDLER =
            new GlobalRequestTcpIpForwardMessageHandler();

    @Override
    public GlobalRequestTcpIpForwardMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        GlobalRequestTcpIpForwardMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return GlobalRequestTcpIpForwardMessageHandler.SERIALIZER.serialize(this);
    }
}
