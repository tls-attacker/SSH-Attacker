/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestUnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestUnknownMessage
        extends SftpRequestExtendedMessage<SftpRequestUnknownMessage> {

    private ModifiableByteArray requestSpecificData;

    public ModifiableByteArray getRequestSpecificData() {
        return requestSpecificData;
    }

    public void setRequestSpecificData(ModifiableByteArray requestSpecificData) {
        this.requestSpecificData = requestSpecificData;
    }

    public void setRequestSpecificData(byte[] requestSpecificData) {
        this.requestSpecificData =
                ModifiableVariableFactory.safelySetValue(
                        this.requestSpecificData, requestSpecificData);
    }

    public void setSoftlyRequestSpecificData(byte[] requestSpecificData) {
        if (this.requestSpecificData == null
                || this.requestSpecificData.getOriginalValue() == null) {
            this.requestSpecificData =
                    ModifiableVariableFactory.safelySetValue(
                            this.requestSpecificData, requestSpecificData);
        }
    }

    @Override
    public SftpRequestUnknownMessageHandler getHandler(SshContext context) {
        return new SftpRequestUnknownMessageHandler(context, this);
    }
}
