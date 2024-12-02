/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_response.SftpResponseUnknownMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseUnknownMessage extends SftpResponseMessage<SftpResponseUnknownMessage> {
    private ModifiableByteArray responseSpecificData;

    public SftpResponseUnknownMessage() {
        super();
    }

    public SftpResponseUnknownMessage(SftpResponseUnknownMessage other) {
        super(other);
        responseSpecificData =
                other.responseSpecificData != null ? other.responseSpecificData.createCopy() : null;
    }

    @Override
    public SftpResponseUnknownMessage createCopy() {
        return new SftpResponseUnknownMessage(this);
    }

    public ModifiableByteArray getResponseSpecificData() {
        return responseSpecificData;
    }

    public void setResponseSpecificData(ModifiableByteArray responseSpecificData) {
        this.responseSpecificData = responseSpecificData;
    }

    public void setResponseSpecificData(byte[] responseSpecificData) {
        this.responseSpecificData =
                ModifiableVariableFactory.safelySetValue(
                        this.responseSpecificData, responseSpecificData);
    }

    public void setSoftlyResponseSpecificData(byte[] responseSpecificData) {
        if (this.responseSpecificData == null
                || this.responseSpecificData.getOriginalValue() == null) {
            this.responseSpecificData =
                    ModifiableVariableFactory.safelySetValue(
                            this.responseSpecificData, responseSpecificData);
        }
    }

    @Override
    public SftpResponseUnknownMessageHandler getHandler(SshContext context) {
        return new SftpResponseUnknownMessageHandler(context, this);
    }
}
