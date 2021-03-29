package de.rub.nds.sshattacker.connection;

import de.rub.nds.sshattacker.exceptions.ConfigurationException;
import java.util.Collection;
import java.util.Set;

/**
 * Provide common alias methods for SSH context/connection bound objects. SSH
 * contexts are referenced by the alias of their connections. Objects
 * implementing this interface provide a uniform way to access aliases that
 * identify the connections they belong to.
 */
public interface Aliasable {

    public abstract void assertAliasesSetProperly() throws ConfigurationException;

    public abstract String aliasesToString();

    public abstract String getFirstAlias();

    public abstract Set<String> getAllAliases();

    public abstract boolean containsAlias(String alias);

    public abstract boolean containsAllAliases(Collection<String> aliases);
}
