/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionNewlineHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class SftpExtensionNewline extends SftpAbstractExtension<SftpExtensionNewline> {

    private ModifiableInteger newlineSeperatorLength;
    private ModifiableString newlineSeperator;

    public SftpExtensionNewline() {
        super();
    }

    public SftpExtensionNewline(SftpExtensionNewline other) {
        super(other);
        newlineSeperatorLength =
                other.newlineSeperatorLength != null
                        ? other.newlineSeperatorLength.createCopy()
                        : null;
        newlineSeperator =
                other.newlineSeperator != null ? other.newlineSeperator.createCopy() : null;
    }

    @Override
    public SftpExtensionNewline createCopy() {
        return new SftpExtensionNewline(this);
    }

    public ModifiableInteger getNewlineSeperatorLength() {
        return newlineSeperatorLength;
    }

    public void setNewlineSeperatorLength(ModifiableInteger newlineSeperatorLength) {
        this.newlineSeperatorLength = newlineSeperatorLength;
    }

    public void setNewlineSeperatorLength(int newlineSeperatorLength) {
        this.newlineSeperatorLength =
                ModifiableVariableFactory.safelySetValue(
                        this.newlineSeperatorLength, newlineSeperatorLength);
    }

    public ModifiableString getNewlineSeperator() {
        return newlineSeperator;
    }

    public void setNewlineSeperator(ModifiableString newlineSeperator) {
        setNewlineSeperator(newlineSeperator, false);
    }

    public void setNewlineSeperator(String newlineSeperator) {
        setNewlineSeperator(newlineSeperator, false);
    }

    public void setNewlineSeperator(ModifiableString newlineSeperator, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNewlineSeperatorLength(
                    newlineSeperator.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.newlineSeperator = newlineSeperator;
    }

    public void setNewlineSeperator(String newlineSeperator, boolean adjustLengthField) {
        this.newlineSeperator =
                ModifiableVariableFactory.safelySetValue(this.newlineSeperator, newlineSeperator);
        if (adjustLengthField) {
            setNewlineSeperatorLength(
                    this.newlineSeperator.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyNewlineSeperator(
            String newlineSeperator, boolean adjustLengthField, Config config) {
        this.newlineSeperator =
                ModifiableVariableFactory.softlySetValue(this.newlineSeperator, newlineSeperator);
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || newlineSeperatorLength == null
                    || newlineSeperatorLength.getOriginalValue() == null) {
                setNewlineSeperatorLength(
                        this.newlineSeperator.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    public static final SftpExtensionNewlineHandler HANDLER = new SftpExtensionNewlineHandler();

    @Override
    public SftpExtensionNewlineHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionNewlineHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionNewlineHandler.SERIALIZER.serialize(this);
    }
}
