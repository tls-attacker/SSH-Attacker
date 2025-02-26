/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.modifiablevariable.path;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.PROPERTY)
public class ModifiablePath extends ModifiableString {

    public ModifiablePath() {
        super();
    }

    public ModifiablePath(String originalValue) {
        super(originalValue);
    }

    public ModifiablePath(ModifiablePath other) {
        super(other);
    }

    @Override
    public ModifiablePath createCopy() {
        return new ModifiablePath(this);
    }

    public static ModifiablePath safelySetValue(ModifiablePath mv, String value) {
        if (mv == null) {
            return new ModifiablePath(value);
        }
        mv.setOriginalValue(value);
        return mv;
    }

    private static ModifiablePath getModifiablePathWithModification(
            VariableModification<String> modification) {
        ModifiablePath modifiablePath = new ModifiablePath();
        modifiablePath.setModification(modification);
        return modifiablePath;
    }

    public static ModifiablePath prependPath(String perpendValue) {
        return getModifiablePathWithModification(
                PathModificationFactory.prependValue(perpendValue));
    }

    public static ModifiablePath appendPath(String appendValue) {
        return getModifiablePathWithModification(PathModificationFactory.appendValue(appendValue));
    }

    public static ModifiablePath insertPath(String insertValue, int position) {
        return getModifiablePathWithModification(
                PathModificationFactory.insertValue(insertValue, position));
    }

    public static ModifiablePath insertDirectoryTraversal(int count, int position) {
        return getModifiablePathWithModification(
                PathModificationFactory.insertDirectoryTraversal(count, position));
    }

    public static ModifiablePath insertDirectorySeperator(int count, int position) {
        return getModifiablePathWithModification(
                PathModificationFactory.insertDirectorySeperator(count, position));
    }

    public static ModifiablePath toggleRoot() {
        return getModifiablePathWithModification(PathModificationFactory.toggleRoot());
    }

    @Override
    public String toString() {
        return "ModifiablePath{"
                + "originalValue='"
                + backslashEscapeString(originalValue)
                + '\''
                + innerToString()
                + '}';
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ModifiablePath that)) {
            return false;
        }

        return getValue() != null ? getValue().equals(that.getValue()) : that.getValue() == null;
    }
}
