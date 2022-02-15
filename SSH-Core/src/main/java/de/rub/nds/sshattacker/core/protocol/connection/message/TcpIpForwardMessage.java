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
import java.nio.charset.StandardCharsets;

public abstract class TcpIpForwardMessage<T extends TcpIpForwardMessage<T>>
        extends GlobalRequestMessage<T> {

    private ModifiableInteger IPAddressToBindLength;
    private ModifiableString IPAddressToBind;
    private ModifiableInteger portToBind;

    protected TcpIpForwardMessage(GlobalRequestType requestType) {
        super(requestType);
    }

    public ModifiableString getIPAddressToBind() {
        return IPAddressToBind;
    }

    public void setIPAddressToBind(ModifiableString IPAddressToBind) {
        this.IPAddressToBind = IPAddressToBind;
    }

    public void setIPAddressToBind(String IPAddressToBind) {
        this.IPAddressToBind =
                ModifiableVariableFactory.safelySetValue(this.IPAddressToBind, IPAddressToBind);
    }

    public void setIPAddressToBind(ModifiableString IPAddressToBind, boolean adjustLengthField) {
        if (adjustLengthField) {
            setIPAddressToBindLength(
                    IPAddressToBind.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.IPAddressToBind = IPAddressToBind;
    }

    public void setIPAddressToBind(String IPAddressToBind, boolean adjustLengthField) {
        if (adjustLengthField) {
            setIPAddressToBindLength(IPAddressToBind.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.IPAddressToBind =
                ModifiableVariableFactory.safelySetValue(this.IPAddressToBind, IPAddressToBind);
    }

    public ModifiableInteger getIPAddressToBindLength() {
        return IPAddressToBindLength;
    }

    public void setIPAddressToBindLength(ModifiableInteger IPAddressToBindLength) {
        this.IPAddressToBindLength = IPAddressToBindLength;
    }

    public void setIPAddressToBindLength(int IPAddressToBindLength) {
        this.IPAddressToBindLength =
                ModifiableVariableFactory.safelySetValue(
                        this.IPAddressToBindLength, IPAddressToBindLength);
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
}
