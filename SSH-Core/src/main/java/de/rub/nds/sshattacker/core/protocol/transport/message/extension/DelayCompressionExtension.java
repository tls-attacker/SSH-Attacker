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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.DelayCompressionExtensionHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class DelayCompressionExtension extends AbstractExtension<DelayCompressionExtension>
        implements HasSentHandler {

    private ModifiableInteger compressionMethodsLength;

    private ModifiableInteger compressionMethodsClientToServerLength;

    private ModifiableString compressionMethodsClientToServer;

    private ModifiableInteger compressionMethodsServerToClientLength;

    private ModifiableString compressionMethodsServerToClient;

    public DelayCompressionExtension() {
        super();
    }

    public DelayCompressionExtension(DelayCompressionExtension other) {
        super(other);
        compressionMethodsLength =
                other.compressionMethodsLength != null
                        ? other.compressionMethodsLength.createCopy()
                        : null;
        compressionMethodsClientToServerLength =
                other.compressionMethodsClientToServerLength != null
                        ? other.compressionMethodsClientToServerLength.createCopy()
                        : null;
        compressionMethodsClientToServer =
                other.compressionMethodsClientToServer != null
                        ? other.compressionMethodsClientToServer.createCopy()
                        : null;
        compressionMethodsServerToClientLength =
                other.compressionMethodsServerToClientLength != null
                        ? other.compressionMethodsServerToClientLength.createCopy()
                        : null;
        compressionMethodsServerToClient =
                other.compressionMethodsServerToClient != null
                        ? other.compressionMethodsServerToClient.createCopy()
                        : null;
    }

    @Override
    public DelayCompressionExtension createCopy() {
        return new DelayCompressionExtension(this);
    }

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

    public void setSoftlyCompressionMethodsLength(int compressionMethodsLength, Config config) {
        if (config.getAlwaysPrepareLengthFields()
                || this.compressionMethodsLength == null
                || this.compressionMethodsLength.getOriginalValue() == null) {
            this.compressionMethodsLength =
                    ModifiableVariableFactory.safelySetValue(
                            this.compressionMethodsLength, compressionMethodsLength);
        }
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
        }
        this.compressionMethodsClientToServer = compressionMethodsClientToServer;
    }

    public void setCompressionMethodsClientToServer(
            String compressionMethodsClientToServer, boolean adjustLengthField) {
        this.compressionMethodsClientToServer =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsClientToServer, compressionMethodsClientToServer);
        if (adjustLengthField) {
            setCompressionMethodsClientToServerLength(
                    this.compressionMethodsClientToServer
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyCompressionMethodsClientToServer(
            List<CompressionMethod> compressionMethodsClientToServer,
            boolean adjustLengthField,
            Config config) {
        if (this.compressionMethodsClientToServer == null
                || this.compressionMethodsClientToServer.getOriginalValue() == null) {
            this.compressionMethodsClientToServer =
                    ModifiableVariableFactory.safelySetValue(
                            this.compressionMethodsClientToServer,
                            Converter.listOfNamesToString(compressionMethodsClientToServer));
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || compressionMethodsClientToServerLength == null
                    || compressionMethodsClientToServerLength.getOriginalValue() == null) {
                setCompressionMethodsClientToServerLength(
                        this.compressionMethodsClientToServer
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setCompressionMethodsClientToServer(
            String[] compressionMethodsClientToServer, boolean adjustLengthField) {
        setCompressionMethodsClientToServer(
                Converter.listOfNamesToString(compressionMethodsClientToServer), adjustLengthField);
    }

    public void setCompressionMethodsClientToServer(
            List<CompressionMethod> compressionMethodsClientToServer, boolean adjustLengthField) {
        setCompressionMethodsClientToServer(
                Converter.listOfNamesToString(compressionMethodsClientToServer), adjustLengthField);
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
        }
        this.compressionMethodsServerToClient = compressionMethodsServerToClient;
    }

    public void setCompressionMethodsServerToClient(
            String compressionMethodsServerToClient, boolean adjustLengthField) {
        this.compressionMethodsServerToClient =
                ModifiableVariableFactory.safelySetValue(
                        this.compressionMethodsServerToClient, compressionMethodsServerToClient);
        if (adjustLengthField) {
            setCompressionMethodsServerToClientLength(
                    this.compressionMethodsServerToClient
                            .getValue()
                            .getBytes(StandardCharsets.US_ASCII)
                            .length);
        }
    }

    public void setSoftlyCompressionMethodsServerToClient(
            List<CompressionMethod> compressionMethodsServerToClient,
            boolean adjustLengthField,
            Config config) {
        if (this.compressionMethodsServerToClient == null
                || this.compressionMethodsServerToClient.getOriginalValue() == null) {
            this.compressionMethodsServerToClient =
                    ModifiableVariableFactory.safelySetValue(
                            this.compressionMethodsServerToClient,
                            Converter.listOfNamesToString(compressionMethodsServerToClient));
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || compressionMethodsServerToClientLength == null
                    || compressionMethodsServerToClientLength.getOriginalValue() == null) {
                setCompressionMethodsServerToClientLength(
                        this.compressionMethodsServerToClient
                                .getValue()
                                .getBytes(StandardCharsets.US_ASCII)
                                .length);
            }
        }
    }

    public void setCompressionMethodsServerToClient(
            String[] compressionMethodsServerToClient, boolean adjustLengthField) {
        setCompressionMethodsServerToClient(
                Converter.listOfNamesToString(compressionMethodsServerToClient), adjustLengthField);
    }

    public void setCompressionMethodsServerToClient(
            List<CompressionMethod> compressionMethodsServerToClient, boolean adjustLengthField) {
        setCompressionMethodsServerToClient(
                Converter.listOfNamesToString(compressionMethodsServerToClient), adjustLengthField);
    }

    public int computeCompressionMethodsLength() {
        return 2 * DataFormatConstants.STRING_SIZE_LENGTH
                + (compressionMethodsClientToServerLength != null
                        ? compressionMethodsClientToServerLength.getValue()
                        : 0)
                + (compressionMethodsServerToClientLength != null
                        ? compressionMethodsServerToClientLength.getValue()
                        : 0);
    }

    public static final DelayCompressionExtensionHandler HANDLER =
            new DelayCompressionExtensionHandler();

    @Override
    public DelayCompressionExtensionHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        DelayCompressionExtensionHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return DelayCompressionExtensionHandler.SERIALIZER.serialize(this);
    }
}
