/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.State;

import jakarta.xml.bind.annotation.XmlTransient;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * An action that can be used for testing or to provide defaults for the filter/ normalize methods.
 */
public class GeneralAction extends SshAction {

    @XmlTransient private final Set<String> aliases = new LinkedHashSet<>();

    public GeneralAction() {}

    public GeneralAction(String alias) {
        this.aliases.add(alias);
    }

    public GeneralAction(Collection<? extends String> aliases) {
        this.aliases.addAll(aliases);
    }

    public GeneralAction(String... aliases) {
        this.aliases.addAll(Arrays.asList(aliases));
    }

    @Override
    public Set<String> getAllAliases() {
        return aliases;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reset() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void normalize() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void normalize(SshAction defaultAction) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void filter() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void filter(SshAction defaultAction) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean executedAsPlanned() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
