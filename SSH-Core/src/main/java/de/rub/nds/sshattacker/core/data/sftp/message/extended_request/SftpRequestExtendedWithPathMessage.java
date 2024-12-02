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
import java.nio.charset.StandardCharsets;

public abstract class SftpRequestExtendedWithPathMessage<
                T extends SftpRequestExtendedWithPathMessage<T>>
        extends SftpRequestExtendedMessage<T> {

    private ModifiableInteger pathLength;
    private ModifiableString path;

    protected SftpRequestExtendedWithPathMessage() {
        super();
    }

    protected SftpRequestExtendedWithPathMessage(SftpRequestExtendedWithPathMessage<T> other) {
        super(other);
        pathLength = other.pathLength != null ? other.pathLength.createCopy() : null;
        path = other.path != null ? other.path.createCopy() : null;
    }

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
        this.path = ModifiableVariableFactory.safelySetValue(this.path, path);
        if (adjustLengthField) {
            setPathLength(this.path.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyPath(String path, boolean adjustLengthField, Config config) {
        if (this.path == null || this.path.getOriginalValue() == null) {
            this.path = ModifiableVariableFactory.safelySetValue(this.path, path);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || pathLength == null
                    || pathLength.getOriginalValue() == null) {
                setPathLength(this.path.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }
}
