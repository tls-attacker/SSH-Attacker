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
import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestTcpIpForwardMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class GlobalRequestTcpIpForwardMessage
        extends GlobalRequestMessage<GlobalRequestTcpIpForwardMessage> {

    private ModifiableInteger ipAddressToBindLength;
    private ModifiableString ipAddressToBind;
    private ModifiableInteger portToBind;

    public GlobalRequestTcpIpForwardMessage() {
        super(GlobalRequestType.TCPIP_FORWARD);
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
        if (adjustLengthField) {
            setIpAddressToBindLength(
                    ipAddressToBind.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.ipAddressToBind = ipAddressToBind;
    }

    public void setIpAddressToBind(String ipAddressToBind, boolean adjustLengthField) {
        if (adjustLengthField) {
            setIpAddressToBindLength(ipAddressToBind.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.ipAddressToBind =
                ModifiableVariableFactory.safelySetValue(this.ipAddressToBind, ipAddressToBind);
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

    public void setPortToBind(Integer portToBind) {
        this.portToBind = ModifiableVariableFactory.safelySetValue(this.portToBind, portToBind);
    }

    @Override
    public GlobalRequestTcpIpForwardMessageHandler getHandler(SshContext context) {
        return new GlobalRequestTcpIpForwardMessageHandler(context, this);
    }
}
