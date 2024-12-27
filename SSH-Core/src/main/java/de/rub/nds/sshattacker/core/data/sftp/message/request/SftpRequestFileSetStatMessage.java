/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestFileSetStatMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class SftpRequestFileSetStatMessage
        extends SftpRequestWithHandleMessage<SftpRequestFileSetStatMessage> {

    @HoldsModifiableVariable private SftpFileAttributes attributes = new SftpFileAttributes();

    public SftpRequestFileSetStatMessage() {
        super();
    }

    public SftpRequestFileSetStatMessage(SftpRequestFileSetStatMessage other) {
        super(other);
        attributes = other.attributes != null ? other.attributes.createCopy() : null;
    }

    @Override
    public SftpRequestFileSetStatMessage createCopy() {
        return new SftpRequestFileSetStatMessage(this);
    }

    public SftpFileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpFileAttributes attributes) {
        this.attributes = attributes;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (attributes != null) {
            holders.addAll(attributes.getAllModifiableVariableHolders());
        }
        return holders;
    }

    @Override
    public SftpRequestFileSetStatMessageHandler getHandler(SshContext context) {
        return new SftpRequestFileSetStatMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestFileSetStatMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
