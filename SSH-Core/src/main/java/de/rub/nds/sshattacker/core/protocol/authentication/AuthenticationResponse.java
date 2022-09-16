/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.xml.bind.annotation.*;
import org.checkerframework.checker.nullness.qual.NonNull;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthenticationResponse
        implements List<AuthenticationResponse.ResponseEntry>, Serializable {

    @XmlElementWrapper
    @XmlElement(name = "responseEntry")
    private final List<ResponseEntry> responseEntries = new ArrayList<>();

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class ResponseEntry implements Serializable {

        private ModifiableInteger responseLength;
        private ModifiableString response;
        private boolean executed;

        public ResponseEntry() {}

        public ResponseEntry(boolean executed) {
            setExecuted(executed);
        }

        public ResponseEntry(String response, boolean executed) {
            setResponse(response, true);
            setExecuted(executed);
        }

        public ModifiableInteger getResponseLength() {
            return responseLength;
        }

        public void setResponseLength(ModifiableInteger responseLength) {
            this.responseLength = responseLength;
        }

        public void setResponseLength(int responseLength) {
            this.responseLength =
                    ModifiableVariableFactory.safelySetValue(this.responseLength, responseLength);
        }

        public ModifiableString getResponse() {
            return response;
        }

        public void setResponse(ModifiableString response) {
            this.response = response;
        }

        public void setResponse(String response) {
            this.response = ModifiableVariableFactory.safelySetValue(this.response, response);
        }

        public void setResponse(ModifiableString response, boolean adjustLengthField) {
            if (adjustLengthField) {
                setResponseLength(response.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
            this.response = response;
        }

        public void setResponse(String response, boolean adjustLengthField) {
            if (adjustLengthField) {
                setResponseLength(response.getBytes(StandardCharsets.UTF_8).length);
            }
            this.response = ModifiableVariableFactory.safelySetValue(this.response, response);
        }

        public boolean isExecuted() {
            return executed;
        }

        public void setExecuted(boolean executed) {
            this.executed = executed;
        }
    }

    // region List interface methods
    @Override
    public int size() {
        return responseEntries.size();
    }

    @Override
    public boolean isEmpty() {
        return responseEntries.isEmpty();
    }

    @Override
    public boolean contains(Object o) {
        return responseEntries.contains(o);
    }

    @Override
    public Iterator<ResponseEntry> iterator() {
        return responseEntries.iterator();
    }

    @Override
    public Object[] toArray() {
        return responseEntries.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        return responseEntries.toArray(a);
    }

    @Override
    public boolean add(ResponseEntry responseEntry) {
        return responseEntries.add(responseEntry);
    }

    @Override
    public boolean remove(Object o) {
        return responseEntries.remove(o);
    }

    @SuppressWarnings("SlowListContainsAll")
    @Override
    public boolean containsAll(@NonNull Collection<?> c) {
        return responseEntries.containsAll(c);
    }

    @Override
    public boolean addAll(@NonNull Collection<? extends ResponseEntry> c) {
        return responseEntries.addAll(c);
    }

    @Override
    public boolean addAll(int index, @NonNull Collection<? extends ResponseEntry> c) {
        return responseEntries.addAll(c);
    }

    @Override
    public boolean removeAll(@NonNull Collection<?> c) {
        return responseEntries.removeAll(c);
    }

    @Override
    public boolean retainAll(@NonNull Collection<?> c) {
        return responseEntries.retainAll(c);
    }

    @Override
    public void clear() {
        responseEntries.clear();
    }

    @Override
    public ResponseEntry get(int index) {
        return responseEntries.get(index);
    }

    @Override
    public ResponseEntry set(int index, ResponseEntry element) {
        return responseEntries.set(index, element);
    }

    @Override
    public void add(int index, ResponseEntry element) {
        responseEntries.add(index, element);
    }

    @Override
    public ResponseEntry remove(int index) {
        return responseEntries.remove(index);
    }

    @Override
    public int indexOf(Object o) {
        return responseEntries.indexOf(o);
    }

    @Override
    public int lastIndexOf(Object o) {
        return responseEntries.lastIndexOf(o);
    }

    @Override
    public ListIterator<ResponseEntry> listIterator() {
        return responseEntries.listIterator();
    }

    @Override
    public ListIterator<ResponseEntry> listIterator(int index) {
        return responseEntries.listIterator(index);
    }

    @Override
    public List<ResponseEntry> subList(int fromIndex, int toIndex) {
        return responseEntries.subList(fromIndex, toIndex);
    }
    // endregion
}
