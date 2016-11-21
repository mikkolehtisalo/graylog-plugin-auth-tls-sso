package org.graylog.plugins.auth.tls.sso;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;

/**
 * Created by mlehtisalo on 10/2/16.
 */
public class CertificateInfo<K, V> extends HashMap<K, V> {

    private static final Logger log = LoggerFactory.getLogger(CertificateInfo.class);

    /** Attempts to add to HashMap. If the HashMap already has such key, logs a warning. Might
     * throw ClassCastException if the V is not compatible with String. Use only with String, String.
     */
    @SuppressWarnings("unchecked")
    public V putLogString(K key, Object value) {
        String val = value.toString();
        if (super.containsKey(key) && super.get(key)!=null) {
            log.warn("Overwriting already existing value {}", key);
        }
        return super.put(key, (V) val);
    }

}
