/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.response.SftpResponseDataMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseDataMessage extends SftpResponseMessage<SftpResponseDataMessage> {

    private ModifiableInteger dataLength;
    private ModifiableByteArray data;

    public SftpResponseDataMessage() {
        super();
    }

    public SftpResponseDataMessage(SftpResponseDataMessage other) {
        super(other);
        dataLength = other.dataLength != null ? other.dataLength.createCopy() : null;
        data = other.data != null ? other.data.createCopy() : null;
    }

    @Override
    public SftpResponseDataMessage createCopy() {
        return new SftpResponseDataMessage(this);
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

    @Override
    public SftpResponseDataMessageHandler getHandler(SshContext context) {
        return new SftpResponseDataMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpResponseDataMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpResponseDataMessageHandler.SERIALIZER.serialize(this);
    }
}
