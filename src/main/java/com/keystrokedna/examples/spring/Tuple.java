package com.keystrokedna.examples.spring;

import lombok.Data;

@Data
public class Tuple<K, V> {

    private final K key;

    private final V value;
}
