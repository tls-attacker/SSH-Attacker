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
import java.nio.charset.StandardCharsets;

public abstract class SftpRequestExtendedWithPathMessage<
                T extends SftpRequestExtendedWithPathMessage<T>>
        extends SftpRequestExtendedMessage<T> {

    private ModifiableInteger pathLength;
    private ModifiableString path;

    public ModifiableInteger getPathLength() {
        return pathLength;
    }

    public void setPathLength(ModifiableInteger pathLength) {
        this.pathLength = pathLength;
    }

    public void setPathLength(int pathLength) {
        this.pathLength = ModifiableVariableFactory.safelySetValue(this.pathLength, pathLength);
    }

    public ModifiableString getPath() {
        return path;
    }

    public void setPath(ModifiableString path) {
        setPath(path, false);
    }

    public void setPath(String path) {
        setPath(path, false);
    }

    public void setPath(ModifiableString path, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPathLength(path.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.path = path;
    }

    public void setPath(String path, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPathLength(path.getBytes(StandardCharsets.UTF_8).length);
        }
        this.path = ModifiableVariableFactory.safelySetValue(this.path, path);
    }
}
