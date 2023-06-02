/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.sshattacker.core.constants.ProtocolMessageType;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.ConnectionMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ConnectionMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ConnectionMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ConnectionMessageSerializer;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.InputStream;
import java.util.Arrays;

public class ConnectionMessage extends ProtocolMessage<ConnectionMessage> {
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] dataConfig = null;

    @ModifiableVariableProperty private ModifiableByteArray data;

    public ConnectionMessage(byte[] dataConfig) {
        super();
        this.dataConfig = dataConfig;
        this.protocolMessageType = ProtocolMessageType.AUTHENTICATION;
    }

    public ConnectionMessage() {
        super();
        this.protocolMessageType = ProtocolMessageType.AUTHENTICATION;
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        if (this.data == null) {
            this.data = new ModifiableByteArray();
        }
        this.data.setOriginalValue(data);
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ApplicationMessage:");
        sb.append("\n  Data: ");
        if (data != null && data.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(data.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        return "APPLICATION";
    }

    @Override
    public String toShortString() {
        return "APP";
    }

    @Override
    public ConnectionMessageHandler getHandler(SshContext sshContext) {
        return new ConnectionMessageHandler(sshContext);
    }

    @Override
    public ConnectionMessageParser getParser(SshContext sshContext, InputStream stream) {
        return new ConnectionMessageParser(stream);
    }

    @Override
    public ConnectionMessagePreparator getPreparator(SshContext sshContext) {
        return new ConnectionMessagePreparator(sshContext.getChooser(), this);
    }

    @Override
    public ConnectionMessageSerializer getSerializer(SshContext sshContext) {
        return new ConnectionMessageSerializer(this);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 43 * hash + Arrays.hashCode(this.dataConfig);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ConnectionMessage other = (ConnectionMessage) obj;
        return Arrays.equals(this.dataConfig, other.dataConfig);
    }
}
