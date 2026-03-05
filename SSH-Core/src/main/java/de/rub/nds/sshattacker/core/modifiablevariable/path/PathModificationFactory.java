/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.modifiablevariable.path;

import de.rub.nds.modifiablevariable.VariableModification;

public final class PathModificationFactory {

    private PathModificationFactory() {
        super();
    }

    public static VariableModification<String> prependValue(String value) {
        return new PathPrependValueModification(value);
    }

    public static VariableModification<String> explicitValue(String value) {
        return new PathExplicitValueModification(value);
    }

    public static VariableModification<String> appendValue(String value) {
        return new PathAppendValueModification(value);
    }

    public static VariableModification<String> insertValue(String value, int position) {
        return new PathInsertValueModification(value, position);
    }

    public static VariableModification<String> delete(int position, int count) {
        return new PathDeleteModification(position, count);
    }

    public static VariableModification<String> insertDirectoryTraversal(int count, int position) {
        return new PathInsertDirectoryTraversalModification(count, position);
    }

    public static VariableModification<String> insertDirectorySeperator(int count, int position) {
        return new PathInsertDirectorySeparatorModification(count, position);
    }

    public static VariableModification<String> toggleRoot() {
        return new PathToggleRootModification();
    }
}
