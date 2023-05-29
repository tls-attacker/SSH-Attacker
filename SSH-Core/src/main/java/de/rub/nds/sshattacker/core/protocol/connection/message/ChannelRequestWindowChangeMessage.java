/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestWindowChangeMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestWindowChangeMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestWindowChangeMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestWindowChangeMessageSerializer;
import java.io.InputStream;

public class ChannelRequestWindowChangeMessage
        extends ChannelRequestMessage<ChannelRequestWindowChangeMessage> {

    private ModifiableInteger widthColumns;
    private ModifiableInteger heightRows;
    private ModifiableInteger widthPixels;
    private ModifiableInteger heightPixels;

    public ModifiableInteger getWidthColumns() {
        return widthColumns;
    }

    public void setWidthColumns(ModifiableInteger widthColumns) {
        this.widthColumns = widthColumns;
    }

    public void setWidthColumns(int widthColumns) {
        this.widthColumns =
                ModifiableVariableFactory.safelySetValue(this.widthColumns, widthColumns);
    }

    public ModifiableInteger getHeightRows() {
        return heightRows;
    }

    public void setHeightRows(ModifiableInteger heightRows) {
        this.heightRows = heightRows;
    }

    public void setHeightRows(int heightRows) {
        this.heightRows = ModifiableVariableFactory.safelySetValue(this.heightRows, heightRows);
    }

    public ModifiableInteger getWidthPixels() {
        return widthPixels;
    }

    public void setWidthPixels(ModifiableInteger widthPixels) {
        this.widthPixels = widthPixels;
    }

    public void setWidthPixels(int widthPixels) {
        this.widthPixels = ModifiableVariableFactory.safelySetValue(this.widthPixels, widthPixels);
    }

    public ModifiableInteger getHeightPixels() {
        return heightPixels;
    }

    public void setHeightPixels(ModifiableInteger heightPixels) {
        this.heightPixels = heightPixels;
    }

    public void setHeightPixels(int heightPixels) {
        this.heightPixels =
                ModifiableVariableFactory.safelySetValue(this.heightPixels, heightPixels);
    }

    @Override
    public ChannelRequestWindowChangeMessageHandler getHandler(SshContext context) {
        return new ChannelRequestWindowChangeMessageHandler(context);
    }

    @Override
    public ChannelRequestWindowChangeMessageParser getParser(
            SshContext context, InputStream inputStream) {
        return new ChannelRequestWindowChangeMessageParser(inputStream);
    }

    @Override
    public ChannelRequestWindowChangeMessagePreparator getPreparator(SshContext context) {
        return new ChannelRequestWindowChangeMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelRequestWindowChangeMessageSerializer getSerializer(SshContext context) {
        return new ChannelRequestWindowChangeMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "REQ_WINDOW_CHANGE";
    }
}
