/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.data.sftp.handler.SftpRequestSymbolicLinkMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class SftpRequestSymbolicLinkMessage
        extends SftpRequestWithPathMessage<SftpRequestSymbolicLinkMessage> {

    // path is the link path

    private ModifiableString targetPath;
    private ModifiableInteger targetPathLength;

    public ModifiableInteger getTargetPathLength() {
        return targetPathLength;
    }

    public void setTargetPathLength(ModifiableInteger targetPathLength) {
        this.targetPathLength = targetPathLength;
    }

    public void setTargetPathLength(int targetPathLength) {
        this.targetPathLength =
                ModifiableVariableFactory.safelySetValue(this.targetPathLength, targetPathLength);
    }

    public ModifiableString getTargetPath() {
        return targetPath;
    }

    public void setTargetPath(ModifiableString targetPath) {
        setTargetPath(targetPath, false);
    }

    public void setTargetPath(String targetPath) {
        setTargetPath(targetPath, false);
    }

    public void setTargetPath(ModifiableString targetPath, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTargetPathLength(targetPath.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.targetPath = targetPath;
    }

    public void setTargetPath(String targetPath, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTargetPathLength(targetPath.getBytes(StandardCharsets.UTF_8).length);
        }
        this.targetPath = ModifiableVariableFactory.safelySetValue(this.targetPath, targetPath);
    }

    @Override
    public SftpRequestSymbolicLinkMessageHandler getHandler(SshContext context) {
        return new SftpRequestSymbolicLinkMessageHandler(context, this);
    }
}
