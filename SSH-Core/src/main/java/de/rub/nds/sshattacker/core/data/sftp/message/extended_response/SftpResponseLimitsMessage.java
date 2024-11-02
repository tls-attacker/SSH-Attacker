/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_response.SftpResponseLimitsMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseLimitsMessage extends SftpResponseMessage<SftpResponseLimitsMessage> {

    private ModifiableLong maximumPacketLength;
    private ModifiableLong maximumReadLength;
    private ModifiableLong maximumWriteLength;
    private ModifiableLong maximumOpenHandles;

    public ModifiableLong getMaximumPacketLength() {
        return maximumPacketLength;
    }

    public void setMaximumPacketLength(ModifiableLong maximumPacketLength) {
        this.maximumPacketLength = maximumPacketLength;
    }

    public void setMaximumPacketLength(long maximumPacketLength) {
        this.maximumPacketLength =
                ModifiableVariableFactory.safelySetValue(
                        this.maximumPacketLength, maximumPacketLength);
    }

    public ModifiableLong getMaximumReadLength() {
        return maximumReadLength;
    }

    public void setMaximumReadLength(ModifiableLong maximumReadLength) {
        this.maximumReadLength = maximumReadLength;
    }

    public void setMaximumReadLength(long maximumReadLength) {
        this.maximumReadLength =
                ModifiableVariableFactory.safelySetValue(this.maximumReadLength, maximumReadLength);
    }

    public ModifiableLong getMaximumWriteLength() {
        return maximumWriteLength;
    }

    public void setMaximumWriteLength(ModifiableLong maximumWriteLength) {
        this.maximumWriteLength = maximumWriteLength;
    }

    public void setMaximumWriteLength(long maximumWriteLength) {
        this.maximumWriteLength =
                ModifiableVariableFactory.safelySetValue(
                        this.maximumWriteLength, maximumWriteLength);
    }

    public ModifiableLong getMaximumOpenHandles() {
        return maximumOpenHandles;
    }

    public void setMaximumOpenHandles(ModifiableLong maximumOpenHandles) {
        this.maximumOpenHandles = maximumOpenHandles;
    }

    public void setMaximumOpenHandles(long maximumOpenHandles) {
        this.maximumOpenHandles =
                ModifiableVariableFactory.safelySetValue(
                        this.maximumOpenHandles, maximumOpenHandles);
    }

    @Override
    public SftpResponseLimitsMessageHandler getHandler(SshContext context) {
        return new SftpResponseLimitsMessageHandler(context, this);
    }
}
