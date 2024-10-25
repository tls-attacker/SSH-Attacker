/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.state;

import de.rub.nds.sshattacker.core.connection.Aliasable;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.exceptions.ContextHandlingException;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Manage SSH contexts. */
public class ContextContainer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Set<String> knownAliases = new HashSet<>();

    private final Map<String, Context> contexts = new HashMap<>();

    /**
     * An inbound SSH context is a context bound to an incoming connection. I.e. it represents a
     * connection that we accepted from a connecting client.
     */
    private final List<Context> inboundSshContexts = new ArrayList<>();

    /**
     * An outbound SSH context is a context bound to an outgoing connection. I.e. it represents a
     * connection established by us to a remote server.
     */
    private final List<Context> outboundSshContexts = new ArrayList<>();

    /**
     * Get the only defined SSH context.
     *
     * <p>Convenience method, useful when working with a single context only.
     *
     * @return the only known SSH context
     * @throws ConfigurationException if there is more than one SSH context in the container
     */
    public Context getContext() {
        if (contexts.isEmpty()) {
            throw new ConfigurationException("No context defined.");
        }
        if (contexts.size() > 1) {
            throw new ConfigurationException(
                    "getSshContext requires an alias if multiple contexts are defined");
        }
        return contexts.entrySet().iterator().next().getValue();
    }

    /**
     * Get SSH context with the given alias.
     *
     * @param alias The alias of the context to retrieve.
     * @return the context with the given connection end alias
     * @throws ConfigurationException if there is no SSH context with the given alias
     */
    public Context getSshContext(String alias) {
        Context ctx = contexts.get(alias);
        if (ctx == null) {
            throw new ConfigurationException("No context defined with alias '" + alias + "'.");
        }
        return ctx;
    }

    public void addContext(Context context) {
        AliasedConnection con = context.getConnection();
        String alias = con.getAlias();
        if (alias == null) {
            throw new ContextHandlingException(
                    "Connection end alias not set (null). Can't add the SSH context.");
        }
        if (containsAlias(alias)) {
            throw new ConfigurationException("Connection end alias already in use: " + alias);
        }

        contexts.put(alias, context);
        knownAliases.add(alias);

        if (con.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
            LOGGER.debug("Adding context {} to inboundSshContexts", alias);
            inboundSshContexts.add(context);
        } else {
            LOGGER.debug("Adding context {} to outboundSshContexts", alias);
            outboundSshContexts.add(context);
        }
    }

    public List<Context> getAllContexts() {
        return new ArrayList<>(contexts.values());
    }

    public List<Context> getInboundContexts() {
        return inboundSshContexts;
    }

    public List<Context> getOutboundContexts() {
        return outboundSshContexts;
    }

    public boolean containsAlias(String alias) {
        return knownAliases.contains(alias);
    }

    public boolean containsAllAliases(Collection<String> aliases) {
        return knownAliases.containsAll(aliases);
    }

    public boolean containsAllAliases(Aliasable aliasable) {
        return knownAliases.containsAll(aliasable.getAllAliases());
    }

    public boolean isEmpty() {
        return contexts.isEmpty();
    }

    public void clear() {
        contexts.clear();
        knownAliases.clear();
        inboundSshContexts.clear();
        outboundSshContexts.clear();
    }

    public void removeSshContext(String alias) {
        if (containsAlias(alias)) {
            Context removeMe = contexts.get(alias);
            inboundSshContexts.remove(removeMe);
            outboundSshContexts.remove(removeMe);
            contexts.remove(alias);
            knownAliases.remove(alias);
        } else {
            LOGGER.debug("No context with alias {} found, nothing to remove", alias);
        }
    }

    /**
     * Replace existing SshContext with new SshContext.
     *
     * <p>The SshContext can only be replaced if the connection of both the new and the old
     * SshContext equal.
     *
     * @param newContext the new SshContext, not null
     * @throws ConfigurationException if the connections of new and old SshContext differ
     */
    public void replaceContext(Context newContext) {
        String alias = newContext.getConnection().getAlias();
        if (!containsAlias(alias)) {
            throw new ConfigurationException("No SshContext to replace for alias " + alias);
        }
        Context replaceMe = contexts.get(alias);
        if (!replaceMe.getConnection().equals(newContext.getConnection())) {
            throw new ContextHandlingException(
                    "Cannot replace SshContext because the new SshContext"
                            + " defines another connection.");
        }
        removeSshContext(alias);
        addContext(newContext);
    }
}
