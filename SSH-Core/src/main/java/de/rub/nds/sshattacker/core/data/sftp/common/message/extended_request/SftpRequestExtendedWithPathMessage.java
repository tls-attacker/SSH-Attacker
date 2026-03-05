/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.modifiablevariable.path.ModifiablePath;
import java.nio.charset.StandardCharsets;

public abstract class SftpRequestExtendedWithPathMessage<
                T extends SftpRequestExtendedWithPathMessage<T>>
        extends SftpRequestExtendedMessage<T> {

    private ModifiableInteger pathLength;
    private ModifiablePath path;

    protected SftpRequestExtendedWithPathMessage() {
        super();
    }

    protected SftpRequestExtendedWithPathMessage(SftpRequestExtendedWithPathMessage<T> other) {
        super(other);
        pathLength = other.pathLength != null ? other.pathLength.createCopy() : null;
        path = other.path != null ? other.path.createCopy() : null;
    }

    @Override
    public abstract SftpRequestExtendedWithPathMessage<T> createCopy();

    public ModifiableInteger getPathLength() {
        return pathLength;
    }

    public void setPathLength(ModifiableInteger pathLength) {
        this.pathLength = pathLength;
    }

    public void setPathLength(int pathLength) {
        this.pathLength = ModifiableVariableFactory.safelySetValue(this.pathLength, pathLength);
    }

    public ModifiablePath getPath() {
        return path;
    }

    public void setPath(ModifiablePath path) {
        setPath(path, false);
    }

    public void setPath(String path) {
        setPath(path, false);
    }

    public void setPath(ModifiablePath path, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPathLength(path.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.path = path;
    }

    public void setPath(String path, boolean adjustLengthField) {
        this.path = ModifiablePath.safelySetValue(this.path, path);
        if (adjustLengthField) {
            setPathLength(this.path.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }
}
