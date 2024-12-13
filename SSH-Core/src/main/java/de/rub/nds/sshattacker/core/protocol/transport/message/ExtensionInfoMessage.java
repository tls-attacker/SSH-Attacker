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
import de.rub.nds.sshattacker.core.protocol.transport.handler.ExtensionInfoMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.List;

public class ExtensionInfoMessage extends SshMessage<ExtensionInfoMessage> {

    private ModifiableInteger extensionCount;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements({
        @XmlElement(type = ServerSigAlgsExtension.class, name = "ServerSigAlgsExtension"),
        @XmlElement(type = DelayCompressionExtension.class, name = "DelayCompressionExtension"),
        @XmlElement(type = PingExtension.class, name = "PingExtension"),
        @XmlElement(
                type = PublicKeyAlgorithmsRoumenPetrovExtension.class,
                name = "PublicKeyAlgorithmsRoumenPetrovExtension"),
        @XmlElement(type = UnknownExtension.class, name = "UnknownExtension")
    })
    private ArrayList<AbstractExtension<?>> extensions = new ArrayList<>();

    public ExtensionInfoMessage() {
        super();
    }

    public ExtensionInfoMessage(ExtensionInfoMessage other) {
        super(other);
        extensionCount = other.extensionCount != null ? other.extensionCount.createCopy() : null;
        if (other.extensions != null) {
            extensions = new ArrayList<>(other.extensions.size());
            for (AbstractExtension<?> item : other.extensions) {
                extensions.add(item != null ? item.createCopy() : null);
            }
        }
    }

    @Override
    public ExtensionInfoMessage createCopy() {
        return new ExtensionInfoMessage(this);
    }

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

    public ArrayList<AbstractExtension<?>> getExtensions() {
        return extensions;
    }

    public void setExtensions(ArrayList<AbstractExtension<?>> extensions) {
        setExtensions(extensions, false);
    }

    public void setExtensions(
            ArrayList<AbstractExtension<?>> extensions, boolean adjustLengthField) {
        if (adjustLengthField) {
            setExtensionCount(extensions.size());
        }
        this.extensions = extensions;
    }

    public void addExtension(AbstractExtension<?> extension) {
        addExtension(extension, false);
    }

    public void addExtension(AbstractExtension<?> extension, boolean adjustLengthField) {
        extensions.add(extension);
    }

    @Override
    public ExtensionInfoMessageHandler getHandler(SshContext context) {
        return new ExtensionInfoMessageHandler(context, this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (extensions != null) {
            holders.addAll(extensions);
        }
        return holders;
    }
}
