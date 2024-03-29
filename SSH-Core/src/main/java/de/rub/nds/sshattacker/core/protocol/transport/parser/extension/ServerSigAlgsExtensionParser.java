/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerSigAlgsExtensionParser extends AbstractExtensionParser<ServerSigAlgsExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerSigAlgsExtensionParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ServerSigAlgsExtension serverSigAlgsExtension) {
        parseExtensionData(serverSigAlgsExtension);
    }

    @Override
    protected ServerSigAlgsExtension createExtension() {
        return new ServerSigAlgsExtension();
    }

    @Override
    protected void parseExtensionValue(ServerSigAlgsExtension extension) {
        parseAcceptedPublicKeyAlgorithmsLength(extension);
        parseAcceptedPublicKeyAlgorithms(extension);
    }

    private void parseAcceptedPublicKeyAlgorithmsLength(ServerSigAlgsExtension extension) {
        extension.setAcceptedPublicKeyAlgorithmsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Accepted public key algorithms length: {}",
                extension.getAcceptedPublicKeyAlgorithmsLength().getValue());
    }

    private void parseAcceptedPublicKeyAlgorithms(ServerSigAlgsExtension extension) {
        extension.setAcceptedPublicKeyAlgorithms(
                parseByteString(
                        extension.getAcceptedPublicKeyAlgorithmsLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Accepted public key algorithms: {}",
                extension.getAcceptedPublicKeyAlgorithms().getValue());
    }
}
