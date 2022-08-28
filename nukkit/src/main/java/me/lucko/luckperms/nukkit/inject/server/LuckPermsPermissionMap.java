/*
 * This file is part of LuckPerms, licensed under the MIT License.
 *
 *  Copyright (c) lucko (Luck) <luck@lucko.me>
 *  Copyright (c) contributors
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

package me.lucko.luckperms.nukkit.inject.server;

import com.google.common.collect.ForwardingMap;
import com.google.common.collect.ImmutableMap;

import it.unimi.dsi.fastutil.booleans.*;
import it.unimi.dsi.fastutil.bytes.*;
import it.unimi.dsi.fastutil.chars.*;
import it.unimi.dsi.fastutil.doubles.*;
import it.unimi.dsi.fastutil.floats.*;
import it.unimi.dsi.fastutil.ints.*;
import it.unimi.dsi.fastutil.longs.*;
import it.unimi.dsi.fastutil.objects.*;
import it.unimi.dsi.fastutil.shorts.*;

import me.lucko.luckperms.common.cache.LoadingMap;
import me.lucko.luckperms.common.plugin.LuckPermsPlugin;
import me.lucko.luckperms.common.treeview.PermissionRegistry;

import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import cn.nukkit.permission.Permission;
import cn.nukkit.plugin.PluginManager;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * A replacement map for the 'permissions' instance in Nukkit's SimplePluginManager.
 *
 * This instance allows LuckPerms to intercept calls to
 * {@link PluginManager#addPermission(Permission)} and record permissions in the
 * {@link PermissionRegistry}.
 *
 * It also allows us to pre-determine child permission relationships.
 *
 * Injected by {@link InjectorPermissionMap}.
 */
public final class LuckPermsPermissionMap extends ForwardingMap<String, Permission> {

    private static final Field PERMISSION_CHILDREN_FIELD;

    static {
        try {
            PERMISSION_CHILDREN_FIELD = Permission.class.getDeclaredField("children");
            PERMISSION_CHILDREN_FIELD.setAccessible(true);
        } catch (NoSuchFieldException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    // Uses perm.getName().toLowerCase(java.util.Locale.ENGLISH); to determine the key
    private final Map<String, Permission> delegate = new ConcurrentHashMap<>();

    // cache from permission --> children
    private final Map<String, Map<String, Boolean>> trueChildPermissions = LoadingMap.of(new ChildPermissionResolver(true));
    private final Map<String, Map<String, Boolean>> falseChildPermissions = LoadingMap.of(new ChildPermissionResolver(false));

    /**
     * The plugin instance
     */
    final LuckPermsPlugin plugin;

    public LuckPermsPermissionMap(LuckPermsPlugin plugin, Map<String, Permission> existingData) {
        this.plugin = plugin;
        putAll(existingData);
    }

    public Map<String, Boolean> getChildPermissions(String permission, boolean value) {
        return value ? this.trueChildPermissions.get(permission) : this.falseChildPermissions.get(permission);
    }

    private void update() {
        this.trueChildPermissions.clear();
        this.falseChildPermissions.clear();
        this.plugin.getUserManager().invalidateAllPermissionCalculators();
        this.plugin.getGroupManager().invalidateAllPermissionCalculators();
    }

    @Override
    protected Map<String, Permission> delegate() {
        return this.delegate;
    }

    @Override
    public Permission put(@NonNull String key, @NonNull Permission value) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(value, "value");

        this.plugin.getPermissionRegistry().insert(key);
        Permission ret = super.put(key, inject(value));
        update();
        return ret;
    }

    @Override
    public void putAll(@NonNull Map<? extends String, ? extends Permission> m) {
        for (Map.Entry<? extends String, ? extends Permission> e : m.entrySet()) {
            this.plugin.getPermissionRegistry().insert(e.getKey());
            super.put(e.getKey(), inject(e.getValue()));
        }
        update();
    }

    @Override
    public Permission remove(@Nullable Object object) {
        if (object == null) {
            return null;
        }
        return uninject(super.remove(object));
    }

    @Override
    public boolean remove(Object key, Object value) {
        return key != null && value != null && super.remove(key, uninject((Permission) value));
    }

    // check for null

    @Override
    public boolean containsKey(@Nullable Object key) {
        return key != null && super.containsKey(key);
    }

    @Override
    public boolean containsValue(@Nullable Object value) {
        return value != null && super.containsValue(value);
    }

    @Override
    public Permission get(@Nullable Object key) {
        if (key == null) {
            return null;
        }
        return super.get(key);
    }

    private final class ChildPermissionResolver implements Function<String, Map<String, Boolean>> {
        private final boolean value;

        private ChildPermissionResolver(boolean value) {
            this.value = value;
        }

        @Override
        public Map<String, Boolean> apply(@NonNull String key) {
            Map<String, Boolean> children = new HashMap<>();
            resolveChildren(children, Collections.singletonMap(key, this.value), false);
            children.remove(key, this.value);
            return ImmutableMap.copyOf(children);
        }
    }

    private void resolveChildren(Map<String, Boolean> accumulator, Map<String, Boolean> children, boolean invert) {
        // iterate through the current known children.
        // the first time this method is called for a given permission, the children map will contain only the permission itself.
        for (Map.Entry<String, Boolean> e : children.entrySet()) {
            if (e == null || e.getKey() == null || e.getValue() == null) {
                continue;
            }

            String key = e.getKey().toLowerCase(Locale.ROOT);

            if (accumulator.containsKey(key)) {
                continue; // Prevent infinite loops
            }

            // xor the value using the parent (nukkit logic, not mine)
            boolean value = e.getValue() ^ invert;
            accumulator.put(key, value);

            // lookup any deeper children & resolve if present
            Permission perm = this.delegate.get(key);
            if (perm != null) {
                resolveChildren(accumulator, perm.getChildren(), !value);
            }
        }
    }

    private Permission inject(Permission permission) {
        if (permission == null) {
            return null;
        }

        try {
            //noinspection unchecked
            Object2BooleanMap<String> children = (Object2BooleanMap<String>) PERMISSION_CHILDREN_FIELD.get(permission);
            while (children instanceof NotifyingChildrenMap) {
                children = ((NotifyingChildrenMap) children).delegate;
            }

            NotifyingChildrenMap notifyingChildren = new NotifyingChildrenMap(children);
            PERMISSION_CHILDREN_FIELD.set(permission, notifyingChildren);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return permission;
    }

    private Permission uninject(Permission permission) {
        if (permission == null) {
            return null;
        }

        try {
            //noinspection unchecked
            Object2BooleanMap<String> children = (Object2BooleanMap<String>) PERMISSION_CHILDREN_FIELD.get(permission);
            while (children instanceof NotifyingChildrenMap) {
                children = ((NotifyingChildrenMap) children).delegate;
            }
            PERMISSION_CHILDREN_FIELD.set(permission, children);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return permission;
    }

    private final class NotifyingChildrenMap implements Object2BooleanMap<String> {
        private final Object2BooleanMap<String> delegate;

        NotifyingChildrenMap(Object2BooleanMap<String> delegate) {
            this.delegate = delegate;

            for (String key : this.delegate.keySet()) {
                LuckPermsPermissionMap.this.plugin.getPermissionRegistry().insert(key);
            }
        }

        @Override
        public Boolean put(@NonNull String key, @NonNull Boolean value) {
            Boolean ret = delegate.put(key, value);
            LuckPermsPermissionMap.this.plugin.getPermissionRegistry().insert(key);
            LuckPermsPermissionMap.this.update();
            return ret;
        }

        @Override
        public boolean put(String key, boolean value) {
            boolean ret = delegate.put(key, value);
            LuckPermsPermissionMap.this.plugin.getPermissionRegistry().insert(key);
            LuckPermsPermissionMap.this.update();
            return ret;
        }

        @Override
        public void putAll(@NonNull Map<? extends String, ? extends Boolean> map) {
            delegate.putAll(map);
            for (String key : map.keySet()) {
                LuckPermsPermissionMap.this.plugin.getPermissionRegistry().insert(key);
            }
            LuckPermsPermissionMap.this.update();
        }

        @Override
        public Boolean remove(@NonNull Object object) {
            Boolean ret = delegate.remove(object);
            LuckPermsPermissionMap.this.update();
            return ret;
        }

        @Override
        public boolean removeBoolean(Object key) {
            boolean ret = delegate.removeBoolean(key);
            LuckPermsPermissionMap.this.update();
            return ret;
        }

        @Override
        public void clear() {
            delegate.clear();
            LuckPermsPermissionMap.this.update();
        }

        // forwarding

        @Override
        public boolean test(String operand) {
            return delegate.test(operand);
        }

        @Override
        public Predicate<String> and(Predicate<? super String> other) {
            return delegate.and(other);
        }

        @Override
        public Predicate<String> negate() {
            return delegate.negate();
        }

        @Override
        public Predicate<String> or(Predicate<? super String> other) {
            return delegate.or(other);
        }

        @Override
        public boolean getBoolean(Object key) {
            return delegate.getBoolean(key);
        }

        @Override
        public Boolean apply(String key) {
            return delegate.apply(key);
        }

        @Override
        public <V> Function<V, Boolean> compose(Function<? super V, ? extends String> before) {
            return delegate.compose(before);
        }

        @Override
        public Boolean get(Object key) {
            return delegate.get(key);
        }

        @Override
        public ObjectSet<String> keySet() {
            return delegate.keySet();
        }

        @Override
        public BooleanCollection values() {
            return delegate.values();
        }

        @Override
        public boolean containsKey(Object key) {
            return delegate.containsKey(key);
        }

        @Override
        public boolean containsValue(boolean value) {
            return delegate.containsValue(value);
        }

        @Override
        public boolean containsValue(Object value) {
            return delegate.containsValue(value);
        }

        @Override
        public void forEach(BiConsumer<? super String, ? super Boolean> consumer) {
            delegate.forEach(consumer);
        }

        @Override
        public void replaceAll(BiFunction<? super String, ? super Boolean, ? extends Boolean> function) {
            delegate.replaceAll(function);
        }

        @Override
        public Boolean putIfAbsent(String key, Boolean value) {
            return delegate.putIfAbsent(key, value);
        }

        @Override
        public boolean remove(Object key, Object value) {
            return delegate.remove(key, value);
        }

        @Override
        public boolean replace(String key, Boolean oldValue, Boolean newValue) {
            return delegate.replace(key, oldValue, newValue);
        }

        @Override
        public Boolean replace(String key, Boolean value) {
            return delegate.replace(key, value);
        }

        @Override
        public Boolean computeIfAbsent(String key, Function<? super String, ? extends Boolean> mappingFunction) {
            return delegate.computeIfAbsent(key, mappingFunction);
        }

        @Override
        public Boolean computeIfPresent(String key, BiFunction<? super String, ? super Boolean, ? extends Boolean> remappingFunction) {
            return delegate.computeIfPresent(key, remappingFunction);
        }

        @Override
        public Boolean compute(String key, BiFunction<? super String, ? super Boolean, ? extends Boolean> remappingFunction) {
            return delegate.compute(key, remappingFunction);
        }

        @Override
        public Boolean merge(String key, Boolean value, BiFunction<? super Boolean, ? super Boolean, ? extends Boolean> remappingFunction) {
            return delegate.merge(key, value, remappingFunction);
        }

        @Override
        public boolean getOrDefault(Object key, boolean defaultValue) {
            return delegate.getOrDefault(key, defaultValue);
        }

        @Override
        public Boolean getOrDefault(Object key, Boolean defaultValue) {
            return delegate.getOrDefault(key, defaultValue);
        }

        @Override
        public boolean putIfAbsent(String key, boolean value) {
            return delegate.putIfAbsent(key, value);
        }

        @Override
        public boolean remove(Object key, boolean value) {
            return delegate.remove(key, value);
        }

        @Override
        public boolean replace(String key, boolean oldValue, boolean newValue) {
            return delegate.replace(key, oldValue, newValue);
        }

        @Override
        public boolean replace(String key, boolean value) {
            return delegate.replace(key, value);
        }

        @Override
        public boolean computeIfAbsent(String key, Predicate<? super String> mappingFunction) {
            return delegate.computeIfAbsent(key, mappingFunction);
        }

        @Override
        public boolean computeBooleanIfAbsent(String key, Predicate<? super String> mappingFunction) {
            return delegate.computeBooleanIfAbsent(key, mappingFunction);
        }

        @Override
        public boolean computeIfAbsent(String key, Object2BooleanFunction<? super String> mappingFunction) {
            return delegate.computeIfAbsent(key, mappingFunction);
        }

        @Override
        public boolean computeBooleanIfAbsentPartial(String key, Object2BooleanFunction<? super String> mappingFunction) {
            return delegate.computeBooleanIfAbsentPartial(key, mappingFunction);
        }

        @Override
        public boolean computeBooleanIfPresent(String key, BiFunction<? super String, ? super Boolean, ? extends Boolean> remappingFunction) {
            return delegate.computeBooleanIfPresent(key, remappingFunction);
        }

        @Override
        public boolean computeBoolean(String key, BiFunction<? super String, ? super Boolean, ? extends Boolean> remappingFunction) {
            return delegate.computeBoolean(key, remappingFunction);
        }

        @Override
        public boolean merge(String key, boolean value, BiFunction<? super Boolean, ? super Boolean, ? extends Boolean> remappingFunction) {
            return delegate.merge(key, value, remappingFunction);
        }

        @Override
        public int size() {
            return delegate.size();
        }

        @Override
        public boolean isEmpty() {
            return delegate.isEmpty();
        }

        @Override
        public void defaultReturnValue(boolean rv) {
            delegate.defaultReturnValue(rv);
        }

        @Override
        public boolean defaultReturnValue() {
            return delegate.defaultReturnValue();
        }

        @Override
        public <T> Function<String, T> andThen(Function<? super Boolean, ? extends T> after) {
            return delegate.andThen(after);
        }

        @Override
        public Object2ByteFunction<String> andThenByte(Boolean2ByteFunction after) {
            return delegate.andThenByte(after);
        }

        @Override
        public Byte2BooleanFunction composeByte(Byte2ObjectFunction<String> before) {
            return delegate.composeByte(before);
        }

        @Override
        public Object2ShortFunction<String> andThenShort(Boolean2ShortFunction after) {
            return delegate.andThenShort(after);
        }

        @Override
        public Short2BooleanFunction composeShort(Short2ObjectFunction<String> before) {
            return delegate.composeShort(before);
        }

        @Override
        public Object2IntFunction<String> andThenInt(Boolean2IntFunction after) {
            return delegate.andThenInt(after);
        }

        @Override
        public Int2BooleanFunction composeInt(Int2ObjectFunction<String> before) {
            return delegate.composeInt(before);
        }

        @Override
        public Object2LongFunction<String> andThenLong(Boolean2LongFunction after) {
            return delegate.andThenLong(after);
        }

        @Override
        public Long2BooleanFunction composeLong(Long2ObjectFunction<String> before) {
            return delegate.composeLong(before);
        }

        @Override
        public Object2CharFunction<String> andThenChar(Boolean2CharFunction after) {
            return delegate.andThenChar(after);
        }

        @Override
        public Char2BooleanFunction composeChar(Char2ObjectFunction<String> before) {
            return delegate.composeChar(before);
        }

        @Override
        public Object2FloatFunction<String> andThenFloat(Boolean2FloatFunction after) {
            return delegate.andThenFloat(after);
        }

        @Override
        public Float2BooleanFunction composeFloat(Float2ObjectFunction<String> before) {
            return delegate.composeFloat(before);
        }

        @Override
        public Object2DoubleFunction<String> andThenDouble(Boolean2DoubleFunction after) {
            return delegate.andThenDouble(after);
        }

        @Override
        public Double2BooleanFunction composeDouble(Double2ObjectFunction<String> before) {
            return delegate.composeDouble(before);
        }

        @Override
        public <T> Object2ObjectFunction<String, T> andThenObject(Boolean2ObjectFunction<? extends T> after) {
            return delegate.andThenObject(after);
        }

        @Override
        public <T> Object2BooleanFunction<T> composeObject(Object2ObjectFunction<? super T, ? extends String> before) {
            return delegate.composeObject(before);
        }

        @Override
        public <T> Object2ReferenceFunction<String, T> andThenReference(Boolean2ReferenceFunction<? extends T> after) {
            return delegate.andThenReference(after);
        }

        @Override
        public <T> Reference2BooleanFunction<T> composeReference(Reference2ObjectFunction<? super T, ? extends String> before) {
            return delegate.composeReference(before);
        }

        @Override
        public ObjectSet<Entry<String>> object2BooleanEntrySet() {
            return delegate.object2BooleanEntrySet();
        }

        @Override
        public ObjectSet<Map.Entry<String, Boolean>> entrySet() {
            return delegate.entrySet();
        }
    }

}
