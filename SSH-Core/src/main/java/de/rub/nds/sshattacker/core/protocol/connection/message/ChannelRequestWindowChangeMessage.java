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
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestWindowChangeMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestWindowChangeMessage
        extends ChannelRequestMessage<ChannelRequestWindowChangeMessage> implements HasSentHandler {

    private ModifiableInteger widthColumns;
    private ModifiableInteger heightRows;
    private ModifiableInteger widthPixels;
    private ModifiableInteger heightPixels;

    public ChannelRequestWindowChangeMessage() {
        super();
    }

    public ChannelRequestWindowChangeMessage(ChannelRequestWindowChangeMessage other) {
        super(other);
        widthColumns = other.widthColumns != null ? other.widthColumns.createCopy() : null;
        heightRows = other.heightRows != null ? other.heightRows.createCopy() : null;
        widthPixels = other.widthPixels != null ? other.widthPixels.createCopy() : null;
        heightPixels = other.heightPixels != null ? other.heightPixels.createCopy() : null;
    }

    @Override
    public ChannelRequestWindowChangeMessage createCopy() {
        return new ChannelRequestWindowChangeMessage(this);
    }

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

    public static final ChannelRequestWindowChangeMessageHandler HANDLER =
            new ChannelRequestWindowChangeMessageHandler();

    @Override
    public ChannelRequestWindowChangeMessageHandler getHandler() {
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
        ChannelRequestWindowChangeMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestWindowChangeMessageHandler.SERIALIZER.serialize(this);
    }
}
