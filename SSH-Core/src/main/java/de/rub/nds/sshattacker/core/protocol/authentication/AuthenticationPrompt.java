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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.util.Converter;
import jakarta.xml.bind.annotation.*;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.*;

@SuppressWarnings({"SlowListContainsAll", "StandardVariableNames"})
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthenticationPrompt implements List<AuthenticationPrompt.PromptEntry>, Serializable {

    @XmlElementWrapper
    @XmlElement(name = "promptEntry")
    private final List<PromptEntry> promptEntries = new ArrayList<>();

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class PromptEntry {

        private ModifiableInteger promptLength;
        private ModifiableString prompt;
        private ModifiableByte echo;

        public ModifiableInteger getPromptLength() {
            return promptLength;
        }

        public void setPromptLength(ModifiableInteger promptLength) {
            this.promptLength = promptLength;
        }

        public void setPromptLength(int promptLength) {
            this.promptLength =
                    ModifiableVariableFactory.safelySetValue(this.promptLength, promptLength);
        }

        public ModifiableString getPrompt() {
            return prompt;
        }

        public void setPrompt(ModifiableString prompt) {
            this.prompt = prompt;
        }

        public void setPrompt(String prompt) {
            this.prompt = ModifiableVariableFactory.safelySetValue(this.prompt, prompt);
        }

        public void setPrompt(ModifiableString prompt, boolean adjustLengthField) {
            if (adjustLengthField) {
                setPromptLength(prompt.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
            this.prompt = prompt;
        }

        public void setPrompt(String prompt, boolean adjustLengthField) {
            this.prompt = ModifiableVariableFactory.safelySetValue(this.prompt, prompt);
            if (adjustLengthField) {
                setPromptLength(this.prompt.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }

        public void setSoftlyPrompt(String prompt, boolean adjustLengthField, Config config) {
            if (this.prompt == null || this.prompt.getOriginalValue() == null) {
                this.prompt = ModifiableVariableFactory.safelySetValue(this.prompt, prompt);
            }
            if (adjustLengthField) {
                if (config.getAlwaysPrepareLengthFields()
                        || promptLength == null
                        || promptLength.getOriginalValue() == null) {
                    setPromptLength(this.prompt.getValue().getBytes(StandardCharsets.UTF_8).length);
                }
            }
        }

        public ModifiableByte getEcho() {
            return echo;
        }

        public void setEcho(ModifiableByte echo) {
            this.echo = echo;
        }

        public void setEcho(byte echo) {
            this.echo = ModifiableVariableFactory.safelySetValue(this.echo, echo);
        }

        public void setSoftlyEcho(byte echo) {
            if (this.echo == null || this.echo.getOriginalValue() == null) {
                this.echo = ModifiableVariableFactory.safelySetValue(this.echo, echo);
            }
        }

        public void setEcho(boolean echo) {
            setEcho(Converter.booleanToByte(echo));
        }
    }

    // region List interface methods
    @Override
    public int size() {
        return promptEntries.size();
    }

    @Override
    public boolean isEmpty() {
        return promptEntries.isEmpty();
    }

    @Override
    public boolean contains(Object o) {
        return promptEntries.contains(o);
    }

    @Override
    public Iterator<PromptEntry> iterator() {
        return promptEntries.iterator();
    }

    @Override
    public Object[] toArray() {
        return promptEntries.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        return promptEntries.toArray(a);
    }

    @Override
    public boolean add(PromptEntry promptEntry) {
        return promptEntries.add(promptEntry);
    }

    @Override
    public boolean remove(Object o) {
        return promptEntries.remove(o);
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return promptEntries.containsAll(c);
    }

    @Override
    public boolean addAll(Collection<? extends PromptEntry> c) {
        return promptEntries.addAll(c);
    }

    @Override
    public boolean addAll(int index, Collection<? extends PromptEntry> c) {
        return promptEntries.addAll(c);
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        return promptEntries.removeAll(c);
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        return promptEntries.retainAll(c);
    }

    @Override
    public void clear() {
        promptEntries.clear();
    }

    @Override
    public PromptEntry get(int index) {
        return promptEntries.get(index);
    }

    @Override
    public PromptEntry set(int index, PromptEntry element) {
        return promptEntries.set(index, element);
    }

    @Override
    public void add(int index, PromptEntry element) {
        promptEntries.add(index, element);
    }

    @Override
    public PromptEntry remove(int index) {
        return promptEntries.remove(index);
    }

    @Override
    public int indexOf(Object o) {
        return promptEntries.indexOf(o);
    }

    @Override
    public int lastIndexOf(Object o) {
        return promptEntries.lastIndexOf(o);
    }

    @Override
    public ListIterator<PromptEntry> listIterator() {
        return promptEntries.listIterator();
    }

    @Override
    public ListIterator<PromptEntry> listIterator(int index) {
        return promptEntries.listIterator(index);
    }

    @Override
    public List<PromptEntry> subList(int fromIndex, int toIndex) {
        return promptEntries.subList(fromIndex, toIndex);
    }
    // endregion
}
