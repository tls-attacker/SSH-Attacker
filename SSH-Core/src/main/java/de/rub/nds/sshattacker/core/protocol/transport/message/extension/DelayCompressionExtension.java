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
import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.DelayCompressionExtensionHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

public class DelayCompressionExtension extends AbstractExtension<DelayCompressionExtension> {

    private ModifiableInteger compressionMethodsLength;

    private ModifiableInteger compressionMethodsClientToServerLength;

    private ModifiableString compressionMethodsClientToServer;

    private ModifiableInteger compressionMethodsServerToClientLength;

    private ModifiableString compressionMethodsServerToClient;

    public ModifiableInteger getCompressionMethodsLength() {
        return compressionMethodsLength;
    }

    public void setCompressionMethodsLength(ModifiableInteger compressionMethodsLength) {
        this.compressionMethodsLength = compressionMethodsLength;
    }

    public void setCompressionMethodsLength(int compressionMethodsLength) {
        this.compressionMethodsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsLength, compressionMethodsLength);
    }

    public ModifiableInteger getCompressionMethodsClientToServerLength() {
        return compressionMethodsClientToServerLength;
    }

    public void setCompressionMethodsClientToServerLength(
            ModifiableInteger compressionMethodsClientToServerLength) {
        this.compressionMethodsClientToServerLength = compressionMethodsClientToServerLength;
    }

    public void setCompressionMethodsClientToServerLength(
            int compressionMethodsClientToServerLength) {
        this.compressionMethodsClientToServerLength =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsClientToServerLength,
                        compressionMethodsClientToServerLength);
    }

    public ModifiableString getCompressionMethodsClientToServer() {
        return compressionMethodsClientToServer;
    }

    public void setCompressionMethodsClientToServer(
            ModifiableString compressionMethodsClientToServer) {
        setCompressionMethodsClientToServer(compressionMethodsClientToServer, false);
    }

    public void setCompressionMethodsClientToServer(String compressionMethodsClientToServer) {
        setCompressionMethodsClientToServer(compressionMethodsClientToServer, false);
    }

    public void setCompressionMethodsClientToServer(String[] compressionMethodsClientToServer) {
        setCompressionMethodsClientToServer(compressionMethodsClientToServer, false);
    }

    public void setCompressionMethodsClientToServer(
            List<CompressionMethod> compressionMethodsClientToServer) {
        setCompressionMethodsClientToServer(compressionMethodsClientToServer, false);
    }

    public void setCompressionMethodsClientToServer(
            ModifiableString compressionMethodsClientToServer, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCompressionMethodsClientToServerLength(
                    compressionMethodsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
            setCompressionMethodsLength(computeCompressionMethodsLength());
        }
        this.compressionMethodsClientToServer = compressionMethodsClientToServer;
    }

    public void setCompressionMethodsClientToServer(
            String compressionMethodsClientToServer, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCompressionMethodsClientToServerLength(
                    compressionMethodsClientToServer.getBytes(StandardCharsets.US_ASCII).length);
            setCompressionMethodsLength(computeCompressionMethodsLength());
        }
        this.compressionMethodsClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsClientToServer, compressionMethodsClientToServer);
    }

    public void setCompressionMethodsClientToServer(
            String[] compressionMethodsClientToServer, boolean adjustLengthField) {
        String nameList =
                String.join(
                        "" + CharConstants.ALGORITHM_SEPARATOR, compressionMethodsClientToServer);
        setCompressionMethodsClientToServer(nameList, adjustLengthField);
    }

    public void setCompressionMethodsClientToServer(
            List<CompressionMethod> compressionMethodsClientToServer, boolean adjustLengthField) {
        String nameList =
                compressionMethodsClientToServer.stream()
                        .map(CompressionMethod::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setCompressionMethodsClientToServer(nameList, adjustLengthField);
    }

    public ModifiableInteger getCompressionMethodsServerToClientLength() {
        return compressionMethodsServerToClientLength;
    }

    public void setCompressionMethodsServerToClientLength(
            ModifiableInteger compressionMethodsServerToClientLength) {
        this.compressionMethodsServerToClientLength = compressionMethodsServerToClientLength;
    }

    public void setCompressionMethodsServerToClientLength(
            int compressionMethodsServerToClientLength) {
        this.compressionMethodsServerToClientLength =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsServerToClientLength,
                        compressionMethodsServerToClientLength);
    }

    public ModifiableString getCompressionMethodsServerToClient() {
        return compressionMethodsServerToClient;
    }

    public void setCompressionMethodsServerToClient(
            ModifiableString compressionMethodsServerToClient) {
        setCompressionMethodsServerToClient(compressionMethodsServerToClient, false);
    }

    public void setCompressionMethodsServerToClient(String compressionMethodsServerToClient) {
        setCompressionMethodsServerToClient(compressionMethodsServerToClient, false);
    }

    public void setCompressionMethodsServerToClient(String[] compressionMethodsServerToClient) {
        setCompressionMethodsServerToClient(compressionMethodsServerToClient, false);
    }

    public void setCompressionMethodsServerToClient(
            List<CompressionMethod> compressionMethodsServerToClient) {
        setCompressionMethodsServerToClient(compressionMethodsServerToClient, false);
    }

    public void setCompressionMethodsServerToClient(
            ModifiableString compressionMethodsServerToClient, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCompressionMethodsServerToClientLength(
                    compressionMethodsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
            setCompressionMethodsLength(computeCompressionMethodsLength());
        }
        this.compressionMethodsServerToClient = compressionMethodsServerToClient;
    }

    public void setCompressionMethodsServerToClient(
            String compressionMethodsServerToClient, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCompressionMethodsServerToClientLength(
                    compressionMethodsServerToClient.getBytes(StandardCharsets.US_ASCII).length);
            setCompressionMethodsLength(computeCompressionMethodsLength());
        }
        this.compressionMethodsServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsServerToClient, compressionMethodsServerToClient);
    }

    public void setCompressionMethodsServerToClient(
            String[] compressionMethodsServerToClient, boolean adjustLengthField) {
        String nameList =
                String.join(
                        "" + CharConstants.ALGORITHM_SEPARATOR, compressionMethodsServerToClient);
        setCompressionMethodsServerToClient(nameList, adjustLengthField);
    }

    public void setCompressionMethodsServerToClient(
            List<CompressionMethod> compressionMethodsServerToClient, boolean adjustLengthField) {
        String nameList =
                compressionMethodsServerToClient.stream()
                        .map(CompressionMethod::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setCompressionMethodsServerToClient(nameList, adjustLengthField);
    }

    private int computeCompressionMethodsLength() {
        return 2 * DataFormatConstants.STRING_SIZE_LENGTH
                + (compressionMethodsClientToServerLength != null
                        ? compressionMethodsClientToServerLength.getValue()
                        : 0)
                + (compressionMethodsServerToClientLength != null
                        ? compressionMethodsServerToClientLength.getValue()
                        : 0);
    }

    @Override
    public DelayCompressionExtensionHandler getHandler(SshContext context) {
        return new DelayCompressionExtensionHandler(context, this);
    }
}
