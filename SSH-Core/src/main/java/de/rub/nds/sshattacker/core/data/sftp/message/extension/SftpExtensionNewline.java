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
import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionNewlineHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class SftpExtensionNewline extends SftpAbstractExtension<SftpExtensionNewline> {

    private ModifiableInteger newlineSeperatorLength;
    private ModifiableString newlineSeperator;

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
        if (adjustLengthField) {
            setNewlineSeperatorLength(newlineSeperator.getBytes(StandardCharsets.UTF_8).length);
        }
        this.newlineSeperator =
                ModifiableVariableFactory.safelySetValue(this.newlineSeperator, newlineSeperator);
    }

    @Override
    public SftpExtensionNewlineHandler getHandler(SshContext context) {
        return new SftpExtensionNewlineHandler(context, this);
    }
}
