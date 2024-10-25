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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.RequestPtyMessageSSHv1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.RequestPtyMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.RequestPtyMessageSSHv1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.RequestPtyMessageSSHv1Serializier;
import java.io.InputStream;

public class RequestPtyMessageSSH1 extends Ssh1Message<RequestPtyMessageSSH1> {

    private ModifiableString termEnvironment;
    private ModifiableInteger hightRows;
    private ModifiableInteger widthColumns;
    private ModifiableInteger widthPixel;
    private ModifiableInteger hightPixel;
    private ModifiableInteger ttyModes;

    public ModifiableString getTermEnvironment() {
        return termEnvironment;
    }

    public void setTermEnvironment(ModifiableString termEnvironment) {
        this.termEnvironment = termEnvironment;
    }

    public void setTermEnvironment(String termEnvironment) {
        this.termEnvironment =
                ModifiableVariableFactory.safelySetValue(this.termEnvironment, termEnvironment);
    }

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

    public ModifiableInteger getTtyModes() {
        return ttyModes;
    }

    public void setTtyModes(ModifiableInteger ttyModes) {
        this.ttyModes = ttyModes;
    }

    public void setTtyModes(int ttyModes) {
        this.ttyModes = ModifiableVariableFactory.safelySetValue(this.ttyModes, ttyModes);
    }

    @Override
    public RequestPtyMessageSSHv1Handler getHandler(SshContext sshContext) {
        return new RequestPtyMessageSSHv1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<RequestPtyMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new RequestPtyMessageSSHv1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<RequestPtyMessageSSH1> getPreparator(SshContext sshContext) {
        return new RequestPtyMessageSSHv1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<RequestPtyMessageSSH1> getSerializer(SshContext sshContext) {
        return new RequestPtyMessageSSHv1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_REQUEST_PTY";
    }
}
