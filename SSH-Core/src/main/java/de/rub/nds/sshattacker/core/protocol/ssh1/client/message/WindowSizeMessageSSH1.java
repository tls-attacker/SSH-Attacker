/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.WindowSizeMessageSSHv1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.WindowSizeMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.WindowSizeMessageSSHv1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.WindowSizeMessageSSHv1Serializier;
import java.io.InputStream;

public class WindowSizeMessageSSH1 extends Ssh1Message<WindowSizeMessageSSH1> {

    private ModifiableInteger hightRows;
    private ModifiableInteger widthColumns;
    private ModifiableInteger widthPixel;
    private ModifiableInteger hightPixel;

    public ModifiableInteger getHightRows() {
        return hightRows;
    }

    public void setHightRows(ModifiableInteger hightRows) {
        this.hightRows = hightRows;
    }

    public void setHightRows(int hightRows) {
        this.hightRows = ModifiableVariableFactory.safelySetValue(this.hightRows, hightRows);
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

    public ModifiableInteger getWidthPixel() {
        return widthPixel;
    }

    public void setWidthPixel(ModifiableInteger widthPixel) {
        this.widthPixel = widthPixel;
    }

    public void setWidthPixel(int widthPixel) {
        this.widthPixel = ModifiableVariableFactory.safelySetValue(this.widthPixel, widthPixel);
    }

    public ModifiableInteger getHightPixel() {
        return hightPixel;
    }

    public void setHightPixel(ModifiableInteger hightPixel) {
        this.hightPixel = hightPixel;
    }

    public void setHightPixel(int hightPixel) {
        this.hightPixel = ModifiableVariableFactory.safelySetValue(this.hightPixel, hightPixel);
    }

    @Override
    public WindowSizeMessageSSHv1Handler getHandler(SshContext sshContext) {
        return new WindowSizeMessageSSHv1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<WindowSizeMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new WindowSizeMessageSSHv1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<WindowSizeMessageSSH1> getPreparator(SshContext sshContext) {
        return new WindowSizeMessageSSHv1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<WindowSizeMessageSSH1> getSerializer(SshContext sshContext) {
        return new WindowSizeMessageSSHv1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_WINDOW_SIZE";
    }
}
