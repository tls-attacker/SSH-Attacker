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
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpAbstractExtensionHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public abstract class SftpAbstractExtension<T extends SftpAbstractExtension<T>>
        extends ModifiableVariableHolder {

    protected ModifiableInteger nameLength;

    protected ModifiableString name;

    protected SftpAbstractExtension() {
        super();
    }

    protected SftpAbstractExtension(SftpAbstractExtension<T> other) {
        super(other);
        nameLength = other.nameLength != null ? other.nameLength.createCopy() : null;
        name = other.name != null ? other.name.createCopy() : null;
    }

    @Override
    public abstract SftpAbstractExtension<T> createCopy();

    public ModifiableInteger getNameLength() {
        return nameLength;
    }

    public void setNameLength(ModifiableInteger nameLength) {
        this.nameLength = nameLength;
    }

    public void setNameLength(int nameLength) {
        this.nameLength = ModifiableVariableFactory.safelySetValue(this.nameLength, nameLength);
    }

    public ModifiableString getName() {
        return name;
    }

    public void setName(ModifiableString name) {
        setName(name, false);
    }

    public void setName(String name) {
        setName(name, false);
    }

    public void setName(SftpExtension extension) {
        setName(extension.getName(), false);
    }

    public void setName(ModifiableString name, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNameLength(name.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.name = name;
    }

    public void setName(String name, boolean adjustLengthField) {
        this.name = ModifiableVariableFactory.safelySetValue(this.name, name);
        if (adjustLengthField) {
            setNameLength(this.name.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setName(SftpExtension extension, boolean adjustLengthField) {
        setName(extension.getName(), adjustLengthField);
    }

    public abstract SftpAbstractExtensionHandler<T> getHandler();

    public abstract void adjustContext(SshContext context);

    public abstract void prepare(Chooser chooser);

    public abstract byte[] serialize();
}
