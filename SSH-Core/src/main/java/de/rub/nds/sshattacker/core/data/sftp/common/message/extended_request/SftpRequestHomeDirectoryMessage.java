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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request.SftpRequestHomeDirectoryMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class SftpRequestHomeDirectoryMessage
        extends SftpRequestExtendedMessage<SftpRequestHomeDirectoryMessage> {

    private ModifiableInteger usernameLength;
    private ModifiableString username;

    public SftpRequestHomeDirectoryMessage() {
        super();
    }

    public SftpRequestHomeDirectoryMessage(SftpRequestHomeDirectoryMessage other) {
        super(other);
        usernameLength = other.usernameLength != null ? other.usernameLength.createCopy() : null;
        username = other.username != null ? other.username.createCopy() : null;
    }

    @Override
    public SftpRequestHomeDirectoryMessage createCopy() {
        return new SftpRequestHomeDirectoryMessage(this);
    }

    public ModifiableInteger getUsernameLength() {
        return usernameLength;
    }

    public void setUsernameLength(ModifiableInteger usernameLength) {
        this.usernameLength = usernameLength;
    }

    public void setUsernameLength(int usernameLength) {
        this.usernameLength =
                ModifiableVariableFactory.safelySetValue(this.usernameLength, usernameLength);
    }

    public ModifiableString getUsername() {
        return username;
    }

    public void setUsername(ModifiableString username) {
        setUsername(username, false);
    }

    public void setUsername(String username) {
        setUsername(username, false);
    }

    public void setUsername(ModifiableString username, boolean adjustLengthField) {
        if (adjustLengthField) {
            setUsernameLength(username.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.username = username;
    }

    public void setUsername(String username, boolean adjustLengthField) {
        this.username = ModifiableVariableFactory.safelySetValue(this.username, username);
        if (adjustLengthField) {
            setUsernameLength(this.username.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public static final SftpRequestHomeDirectoryMessageHandler HANDLER =
            new SftpRequestHomeDirectoryMessageHandler();

    @Override
    public SftpRequestHomeDirectoryMessageHandler getHandler() {
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
        SftpRequestHomeDirectoryMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestHomeDirectoryMessageHandler.SERIALIZER.serialize(this);
    }
}
