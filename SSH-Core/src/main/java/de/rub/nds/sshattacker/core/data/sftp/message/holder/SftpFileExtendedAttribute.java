/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.holder;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.holder.SftpFileExtendedAttributeHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.nio.charset.StandardCharsets;

@XmlAccessorType(XmlAccessType.FIELD)
public class SftpFileExtendedAttribute extends ModifiableVariableHolder {

    private ModifiableInteger typeLength;
    private ModifiableString type;
    private ModifiableInteger dataLength;
    private ModifiableByteArray data;

    public ModifiableInteger getTypeLength() {
        return typeLength;
    }

    public void setTypeLength(ModifiableInteger typeLength) {
        this.typeLength = typeLength;
    }

    public void setTypeLength(int typeLength) {
        this.typeLength = ModifiableVariableFactory.safelySetValue(this.typeLength, typeLength);
    }

    public ModifiableString getType() {
        return type;
    }

    public void setType(ModifiableString type) {
        setType(type, false);
    }

    public void setType(String type) {
        setType(type, false);
    }

    public void setType(ModifiableString type, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTypeLength(type.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.type = type;
    }

    public void setType(String type, boolean adjustLengthField) {
        this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
        if (adjustLengthField) {
            setTypeLength(this.type.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSoftlyType(String type, boolean adjustLengthField, Config config) {
        if (this.type == null || this.type.getOriginalValue() == null) {
            this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || typeLength == null
                    || typeLength.getOriginalValue() == null) {
                setTypeLength(this.type.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
    }

    public ModifiableInteger getDataLength() {
        return dataLength;
    }

    public void setDataLength(ModifiableInteger dataLength) {
        this.dataLength = dataLength;
    }

    public void setDataLength(int dataLength) {
        this.dataLength = ModifiableVariableFactory.safelySetValue(this.dataLength, dataLength);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        setData(data, false);
    }

    public void setData(byte[] data) {
        setData(data, false);
    }

    public void setData(ModifiableByteArray data, boolean adjustLengthField) {
        this.data = data;
        if (adjustLengthField) {
            setDataLength(this.data.getValue().length);
        }
    }

    public void setData(byte[] data, boolean adjustLengthField) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
        if (adjustLengthField) {
            setDataLength(this.data.getValue().length);
        }
    }

    public void setSoftlyData(byte[] data, boolean adjustLengthField, Config config) {
        if (this.data == null || this.data.getOriginalValue() == null) {
            this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || dataLength == null
                    || dataLength.getOriginalValue() == null) {
                setDataLength(this.data.getValue().length);
            }
        }
    }

    public SftpFileExtendedAttributeHandler getHandler(SshContext context) {
        return new SftpFileExtendedAttributeHandler(context, this);
    }
}
