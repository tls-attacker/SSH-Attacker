/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.path.ModifiablePath;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestSymbolicLinkMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class SftpRequestSymbolicLinkMessage
        extends SftpRequestWithPathMessage<SftpRequestSymbolicLinkMessage> {

    // path is the link path

    // Note that OpenSSH and some other Implementations (e.g. ProFTPD, Sun SSH) reverses the order
    // of link path and target path

    private ModifiablePath targetPath;
    private ModifiableInteger targetPathLength;

    public SftpRequestSymbolicLinkMessage() {
        super();
    }

    public SftpRequestSymbolicLinkMessage(SftpRequestSymbolicLinkMessage other) {
        super(other);
        targetPath = other.targetPath != null ? other.targetPath.createCopy() : null;
        targetPathLength =
                other.targetPathLength != null ? other.targetPathLength.createCopy() : null;
    }

    @Override
    public SftpRequestSymbolicLinkMessage createCopy() {
        return new SftpRequestSymbolicLinkMessage(this);
    }

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

    public ModifiablePath getTargetPath() {
        return targetPath;
    }

    public void setTargetPath(ModifiablePath targetPath) {
        setTargetPath(targetPath, false);
    }

    public void setTargetPath(String targetPath) {
        setTargetPath(targetPath, false);
    }

    public void setTargetPath(ModifiablePath targetPath, boolean adjustLengthField) {
        if (adjustLengthField) {
            setTargetPathLength(targetPath.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.targetPath = targetPath;
    }

    public void setTargetPath(String targetPath, boolean adjustLengthField) {
        this.targetPath = ModifiableVariableFactory.safelySetValue(this.targetPath, targetPath);
        if (adjustLengthField) {
            setTargetPathLength(this.targetPath.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyTargetPath(String targetPath, boolean adjustLengthField, Config config) {
        if (this.targetPath == null || this.targetPath.getOriginalValue() == null) {
            this.targetPath = ModifiableVariableFactory.safelySetValue(this.targetPath, targetPath);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || targetPathLength == null
                    || targetPathLength.getOriginalValue() == null) {
                setTargetPathLength(
                        this.targetPath.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    @Override
    public SftpRequestSymbolicLinkMessageHandler getHandler(SshContext context) {
        return new SftpRequestSymbolicLinkMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestSymbolicLinkMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestSymbolicLinkMessageHandler.SERIALIZER.serialize(this);
    }
}
