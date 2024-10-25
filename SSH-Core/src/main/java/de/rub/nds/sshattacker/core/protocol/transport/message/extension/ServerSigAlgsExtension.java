/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.ServerSigAlgsExtensionHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.ServerSigAlgsExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.ServerSigAlgsExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.ServerSigAlgsExtensionSerializer;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Class for "server-sig-algs"-extension sent by server structure: extension-name string
 * "server-sig-algs" extension-value name-list public_key_algorithms_accepted <br>
 * NOTE: name-list := string containing a comma-separated list of names (4 byte length field
 * followed by a comma-separated list of zero or more names) <br>
 * This extension is sent by a server and contains a list of all public key algorithms the server
 * can process for public key authentification
 */
public class ServerSigAlgsExtension extends AbstractExtension<ServerSigAlgsExtension> {

    private ModifiableInteger acceptedPublicKeyAlgorithmsLength;
    private ModifiableString acceptedPublicKeyAlgorithms;

    public ModifiableInteger getAcceptedPublicKeyAlgorithmsLength() {
        return acceptedPublicKeyAlgorithmsLength;
    }

    public void setAcceptedPublicKeyAlgorithmsLength(
            ModifiableInteger acceptedPublicKeyAlgorithmsLength) {
        this.acceptedPublicKeyAlgorithmsLength = acceptedPublicKeyAlgorithmsLength;
    }

    public void setAcceptedPublicKeyAlgorithmsLength(int acceptedPublicKeyAlgorithmsLength) {
        this.acceptedPublicKeyAlgorithmsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.acceptedPublicKeyAlgorithmsLength, acceptedPublicKeyAlgorithmsLength);
    }

    public ModifiableString getAcceptedPublicKeyAlgorithms() {
        return acceptedPublicKeyAlgorithms;
    }

    public void setAcceptedPublicKeyAlgorithms(ModifiableString publicKeyAlgorithms) {
        setAcceptedPublicKeyAlgorithms(publicKeyAlgorithms, false);
    }

    public void setAcceptedPublicKeyAlgorithms(String publicKeyAlgorithms) {
        setAcceptedPublicKeyAlgorithms(publicKeyAlgorithms, false);
    }

    public void setAcceptedPublicKeyAlgorithms(String[] publicKeyAlgorithms) {
        setAcceptedPublicKeyAlgorithms(publicKeyAlgorithms, false);
    }

    public void setAcceptedPublicKeyAlgorithms(List<PublicKeyAlgorithm> publicKeyAlgorithms) {
        setAcceptedPublicKeyAlgorithms(publicKeyAlgorithms, false);
    }

    public void setAcceptedPublicKeyAlgorithms(
            ModifiableString publicKeyAlgorithms, boolean adjustLengthField) {
        if (adjustLengthField) {
            setAcceptedPublicKeyAlgorithmsLength(
                    publicKeyAlgorithms.getValue().getBytes(StandardCharsets.US_ASCII).length);
            setAcceptedPublicKeyAlgorithmsLength(acceptedPublicKeyAlgorithmsLength.getValue());
        }
        acceptedPublicKeyAlgorithms = publicKeyAlgorithms;
    }

    public void setAcceptedPublicKeyAlgorithms(
            String publicKeyAlgorithms, boolean adjustLengthField) {
        if (adjustLengthField) {
            setAcceptedPublicKeyAlgorithmsLength(
                    publicKeyAlgorithms.getBytes(StandardCharsets.US_ASCII).length);
            setAcceptedPublicKeyAlgorithmsLength(acceptedPublicKeyAlgorithmsLength.getValue());
        }
        acceptedPublicKeyAlgorithms =
                ModifiableVariableFactory.safelySetValue(
                        acceptedPublicKeyAlgorithms, publicKeyAlgorithms);
    }

    public void setAcceptedPublicKeyAlgorithms(
            String[] publicKeyAlgorithms, boolean adjustLengthField) {
        String nameList = String.join("" + CharConstants.ALGORITHM_SEPARATOR, publicKeyAlgorithms);
        setAcceptedPublicKeyAlgorithms(nameList, adjustLengthField);
    }

    public void setAcceptedPublicKeyAlgorithms(
            List<PublicKeyAlgorithm> publicKeyAlgorithms, boolean adjustLengthField) {
        String nameList =
                publicKeyAlgorithms.stream()
                        .map(PublicKeyAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setAcceptedPublicKeyAlgorithms(nameList, adjustLengthField);
    }

    @Override
    public ServerSigAlgsExtensionHandler getHandler(SshContext context) {
        return new ServerSigAlgsExtensionHandler(context, this);
    }

    @Override
    public ServerSigAlgsExtensionParser getParser(SshContext context, InputStream stream) {
        return new ServerSigAlgsExtensionParser(stream);
    }

    @Override
    public ServerSigAlgsExtensionPreparator getPreparator(SshContext sshContext) {
        return new ServerSigAlgsExtensionPreparator(sshContext.getChooser(), this);
    }

    @Override
    public ServerSigAlgsExtensionSerializer getSerializer(SshContext sshContext) {
        return new ServerSigAlgsExtensionSerializer(this);
    }
}
