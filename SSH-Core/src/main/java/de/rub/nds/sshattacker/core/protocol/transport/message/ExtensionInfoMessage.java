/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.ExtensionInfoMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.UnknownExtension;
import de.rub.nds.sshattacker.core.state.SshContext;

import jakarta.xml.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

public class ExtensionInfoMessage extends SshMessage<ExtensionInfoMessage> {

    private ModifiableInteger extensionCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            value = {
                @XmlElement(type = ServerSigAlgsExtension.class, name = "ServerSigAlgsExtension"),
                @XmlElement(
                        type = DelayCompressionExtension.class,
                        name = "DelayCompressionExtension"),
                @XmlElement(type = UnknownExtension.class, name = "UnknownExtension")
            })
    private List<AbstractExtension<?>> extensions = new ArrayList<>();

    public ModifiableInteger getExtensionCount() {
        return extensionCount;
    }

    public void setExtensionCount(ModifiableInteger extensionCount) {
        this.extensionCount = extensionCount;
    }

    public void setExtensionCount(int extensionCount) {
        this.extensionCount =
                ModifiableVariableFactory.safelySetValue(this.extensionCount, extensionCount);
    }

    public List<AbstractExtension<?>> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<AbstractExtension<?>> extensions) {
        setExtensions(extensions, false);
    }

    public void setExtensions(List<AbstractExtension<?>> extensions, boolean adjustLengthField) {
        if (adjustLengthField) {
            setExtensionCount(extensions.size());
        }
        this.extensions = extensions;
    }

    public void addExtension(AbstractExtension<?> extension) {
        extensions.add(extension);
    }

    @Override
    public SshMessageHandler<ExtensionInfoMessage> getHandler(SshContext context) {
        return new ExtensionInfoMessageHandler(context, this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        holders.addAll(extensions);
        return holders;
    }
}
