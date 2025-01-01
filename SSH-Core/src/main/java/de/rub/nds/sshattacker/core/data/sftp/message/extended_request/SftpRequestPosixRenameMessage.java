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
import de.rub.nds.modifiablevariable.path.ModifiablePath;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestPosixRenameMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class SftpRequestPosixRenameMessage
        extends SftpRequestExtendedWithPathMessage<SftpRequestPosixRenameMessage> {

    // path is the old path

    private ModifiableInteger newPathLength;
    private ModifiablePath newPath;

    public SftpRequestPosixRenameMessage() {
        super();
    }

    public SftpRequestPosixRenameMessage(SftpRequestPosixRenameMessage other) {
        super(other);
        newPathLength = other.newPathLength != null ? other.newPathLength.createCopy() : null;
        newPath = other.newPath != null ? other.newPath.createCopy() : null;
    }

    @Override
    public SftpRequestPosixRenameMessage createCopy() {
        return new SftpRequestPosixRenameMessage(this);
    }

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

    public ModifiablePath getNewPath() {
        return newPath;
    }

    public void setNewPath(ModifiablePath newPath) {
        setNewPath(newPath, false);
    }

    public void setNewPath(String newPath) {
        setNewPath(newPath, false);
    }

    public void setNewPath(ModifiablePath newPath, boolean adjustLengthField) {
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

    public static final SftpRequestPosixRenameMessageHandler HANDLER =
            new SftpRequestPosixRenameMessageHandler();

    @Override
    public SftpRequestPosixRenameMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestPosixRenameMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestPosixRenameMessageHandler.SERIALIZER.serialize(this);
    }
}
