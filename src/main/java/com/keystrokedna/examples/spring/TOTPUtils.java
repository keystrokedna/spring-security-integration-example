package com.keystrokedna.examples.spring;

import org.springframework.security.core.userdetails.User;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class TOTPUtils {

    public static String QR_PREFIX = "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=";

    public static String APP_NAME = "KeystrokeDNAIntegration";

    public static String secretFromUsername(String username) {
        String s = username.replaceAll("[^A-Za-z0-9]", "");
        return s.substring(0, Math.min(10, s.length()));
    }

    public static String generateQRUrl(User user) throws UnsupportedEncodingException {
        String secret = secretFromUsername(user.getUsername()); // never use username as secret :) for demo purpose only
        return QR_PREFIX + URLEncoder.encode(String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                APP_NAME, user.getUsername(), secret, APP_NAME), "UTF-8");
    }
}
