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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestTcpIpForwardMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestTcpIpForwardMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestTcpIpForwardMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestTcpIpForwardMessageSerializer;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class GlobalRequestTcpIpForwardMessage
        extends GlobalRequestMessage<GlobalRequestTcpIpForwardMessage> {

    private ModifiableInteger ipAddressToBindLength;
    private ModifiableString ipAddressToBind;
    private ModifiableInteger portToBind;

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

    public void setPortToBind(Integer portToBind) {
        this.portToBind = ModifiableVariableFactory.safelySetValue(this.portToBind, portToBind);
    }

    @Override
    public GlobalRequestTcpIpForwardMessageHandler getHandler(SshContext context) {
        return new GlobalRequestTcpIpForwardMessageHandler(context);
    }

    @Override
    public SshMessageParser<GlobalRequestTcpIpForwardMessage> getParser(
            SshContext context, InputStream stream) {
        return new GlobalRequestTcpIpForwardMessageParser(stream);
    }

    @Override
    public SshMessagePreparator<GlobalRequestTcpIpForwardMessage> getPreparator(
            SshContext context) {
        return new GlobalRequestTcpIpForwardMessagePreparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<GlobalRequestTcpIpForwardMessage> getSerializer(
            SshContext context) {
        return new GlobalRequestTcpIpForwardMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "TCPIP_FW";
    }
}
