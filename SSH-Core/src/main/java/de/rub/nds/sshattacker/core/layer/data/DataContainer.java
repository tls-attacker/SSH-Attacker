/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.data;

import de.rub.nds.sshattacker.core.layer.context.LayerContext;
import java.io.InputStream;

/**
 * All protocol messages are abstracted with the DataContainer interface. For SSH-Attacker to work
 * with data it only needs to know how to parse, prepare, serialize and handle the message. All
 * messages must therefore provide this functionality.
 */
public interface DataContainer<
        Container extends DataContainer<?, ?>, Context extends LayerContext> {

    public Parser<Container> getParser(Context context, InputStream stream);

    public Preparator<Container> getPreparator(Context context);

    public Serializer<Container> getSerializer(Context context);

    public Handler<Container> getHandler(Context context);

    public default boolean isRequired() {
        return true;
    }

    public default String toCompactString() {
        return toString();
    }

    public default String toShortString() {
        return toCompactString();
    }
}
