/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.AuthenticationMessageHandler;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.AuthenticationMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.AuthenticationMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.AuthenticationMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.InputStream;
import java.util.Arrays;

public class AuthenticationMessage extends ProtocolMessage<AuthenticationMessage> {
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] dataConfig = null;

    @ModifiableVariableProperty private ModifiableByteArray data;

    public AuthenticationMessage(byte[] dataConfig) {
        super();
        this.dataConfig = dataConfig;
    }

    public AuthenticationMessage() {
        super();
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
    public AuthenticationMessageHandler getHandler(SshContext sshContext) {
        return new AuthenticationMessageHandler(sshContext);
    }

    @Override
    public AuthenticationMessageParser getParser(SshContext sshContext, InputStream stream) {
        return new AuthenticationMessageParser(stream);
    }

    @Override
    public AuthenticationMessagePreparator getPreparator(SshContext sshContext) {
        return new AuthenticationMessagePreparator(sshContext.getChooser(), this);
    }

    @Override
    public AuthenticationMessageSerializer getSerializer(SshContext sshContext) {
        return new AuthenticationMessageSerializer(this);
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
        final AuthenticationMessage other = (AuthenticationMessage) obj;
        return Arrays.equals(this.dataConfig, other.dataConfig);
    }
}
