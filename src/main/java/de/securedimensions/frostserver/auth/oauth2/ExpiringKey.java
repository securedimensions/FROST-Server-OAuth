/*
 * Copyright (C) 2023 Secure Dimensions GmbH, D-81377
 * Munich, Germany.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package de.securedimensions.frostserver.auth.oauth2;

import java.util.Objects;

/*
From https://stackoverflow.com/questions/49560258/is-there-an-expiring-map-in-java-that-expires-elements-after-a-period-of-time-si
 */
public class ExpiringKey<T> {

    private final T key;
    private final long expirationTimestamp;

    public ExpiringKey(T key) {
        this.key = key;
        expirationTimestamp = Long.MAX_VALUE;
    }

    public ExpiringKey(T key, long ttlInMillis) {
        this.key = key;
        expirationTimestamp = System.currentTimeMillis() + ttlInMillis;
    }

    public T getKey() {
        return key;
    }

    public boolean isExpired() {
        return System.currentTimeMillis() > expirationTimestamp;
    }

    @Override
    public int hashCode() {
        return Objects.hash(key);
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof ExpiringKey<?>) {
            return this.getKey().toString().equalsIgnoreCase(((ExpiringKey) other).getKey().toString());
        }
        return false;
    }
}
