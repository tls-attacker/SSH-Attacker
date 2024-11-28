/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestHardlinkMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class SftpRequestHardlinkMessage
        extends SftpRequestExtendedWithPathMessage<SftpRequestHardlinkMessage> {

    // path is the old path

    private ModifiableInteger newPathLength;
    private ModifiableString newPath;

    public ModifiableInteger getNewPathLength() {
        return newPathLength;
    }

    public void setNewPathLength(ModifiableInteger newPathLength) {
        this.newPathLength = newPathLength;
    }

    public void setNewPathLength(int newPathLength) {
        this.newPathLength =
                ModifiableVariableFactory.safelySetValue(this.newPathLength, newPathLength);
    }

    public ModifiableString getNewPath() {
        return newPath;
    }

    public void setNewPath(ModifiableString newPath) {
        setNewPath(newPath, false);
    }

    public void setNewPath(String newPath) {
        setNewPath(newPath, false);
    }

    public void setNewPath(ModifiableString newPath, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNewPathLength(newPath.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.newPath = newPath;
    }

    public void setNewPath(String newPath, boolean adjustLengthField) {
        this.newPath = ModifiableVariableFactory.safelySetValue(this.newPath, newPath);
        if (adjustLengthField) {
            setNewPathLength(this.newPath.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyNewPath(String newPath, boolean adjustLengthField, Config config) {
        if (this.newPath == null || this.newPath.getOriginalValue() == null) {
            this.newPath = ModifiableVariableFactory.safelySetValue(this.newPath, newPath);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || newPathLength == null
                    || newPathLength.getOriginalValue() == null) {
                setNewPathLength(this.newPath.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    @Override
    public SftpRequestHardlinkMessageHandler getHandler(SshContext context) {
        return new SftpRequestHardlinkMessageHandler(context, this);
    }
}
