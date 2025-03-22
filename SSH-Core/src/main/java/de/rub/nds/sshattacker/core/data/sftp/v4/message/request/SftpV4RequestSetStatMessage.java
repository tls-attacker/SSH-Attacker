/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.message.request;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestWithPathMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.handler.request.SftpV4RequestSetStatMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class SftpV4RequestSetStatMessage
        extends SftpRequestWithPathMessage<SftpV4RequestSetStatMessage> {

    @HoldsModifiableVariable private SftpV4FileAttributes attributes = new SftpV4FileAttributes();

    public SftpV4RequestSetStatMessage() {
        super();
    }

    public SftpV4RequestSetStatMessage(SftpV4RequestSetStatMessage other) {
        super(other);
        attributes = other.attributes != null ? other.attributes.createCopy() : null;
    }

    @Override
    public SftpV4RequestSetStatMessage createCopy() {
        return new SftpV4RequestSetStatMessage(this);
    }

    public SftpV4FileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpV4FileAttributes attributes) {
        this.attributes = attributes;
    }

    public static final SftpV4RequestSetStatMessageHandler HANDLER =
            new SftpV4RequestSetStatMessageHandler();

    @Override
    public SftpV4RequestSetStatMessageHandler getHandler() {
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
        SftpV4RequestSetStatMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpV4RequestSetStatMessageHandler.SERIALIZER.serialize(this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (attributes != null) {
            holders.addAll(attributes.getAllModifiableVariableHolders());
        }
        return holders;
    }
}
