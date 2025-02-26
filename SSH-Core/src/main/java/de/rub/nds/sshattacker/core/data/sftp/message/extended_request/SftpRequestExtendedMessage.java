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
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestMessage;
import java.nio.charset.StandardCharsets;

public abstract class SftpRequestExtendedMessage<T extends SftpRequestExtendedMessage<T>>
        extends SftpRequestMessage<T> {

    private ModifiableString extendedRequestName;
    private ModifiableInteger extendedRequestNameLength;

    protected SftpRequestExtendedMessage() {
        super();
    }

    protected SftpRequestExtendedMessage(SftpRequestExtendedMessage<T> other) {
        super(other);
        extendedRequestName =
                other.extendedRequestName != null ? other.extendedRequestName.createCopy() : null;
        extendedRequestNameLength =
                other.extendedRequestNameLength != null
                        ? other.extendedRequestNameLength.createCopy()
                        : null;
    }

    @Override
    public abstract SftpRequestExtendedMessage<T> createCopy();

    public ModifiableInteger getExtendedRequestNameLength() {
        return extendedRequestNameLength;
    }

    public void setExtendedRequestNameLength(ModifiableInteger extendedRequestNameLength) {
        this.extendedRequestNameLength = extendedRequestNameLength;
    }

    public void setExtendedRequestNameLength(int extendedRequestNameLength) {
        this.extendedRequestNameLength =
                ModifiableVariableFactory.safelySetValue(
                        this.extendedRequestNameLength, extendedRequestNameLength);
    }

    public ModifiableString getExtendedRequestName() {
        return extendedRequestName;
    }

    public void setExtendedRequestName(ModifiableString extendedRequestName) {
        setExtendedRequestName(extendedRequestName, false);
    }

    public void setExtendedRequestName(String extendedRequestName) {
        setExtendedRequestName(extendedRequestName, false);
    }

    public void setExtendedRequestName(SftpExtension extension) {
        setExtendedRequestName(extension.getName());
    }

    public void setExtendedRequestName(
            ModifiableString extendedRequestName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setExtendedRequestNameLength(
                    extendedRequestName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.extendedRequestName = extendedRequestName;
    }

    public void setExtendedRequestName(String extendedRequestName, boolean adjustLengthField) {
        this.extendedRequestName =
                ModifiableVariableFactory.safelySetValue(
                        this.extendedRequestName, extendedRequestName);
        if (adjustLengthField) {
            setExtendedRequestNameLength(
                    this.extendedRequestName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setExtendedRequestName(SftpExtension extension, boolean adjustLengthField) {
        setExtendedRequestName(extension.getName(), adjustLengthField);
    }
}
