package com.yang.TestDemo;

import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


public class MyPasswordEncoder implements PasswordEncoder{
    private final static String SALT = "123456";
    @Override
    public String encode(CharSequence rawPassword) {
        Md5PasswordEncoder encoder = new Md5PasswordEncoder();

        return encoder.encodePassword(rawPassword.toString(),SALT);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String s) {
        Md5PasswordEncoder encoder = new Md5PasswordEncoder();
        return encoder.isPasswordValid(s,rawPassword.toString(),SALT);
    }
}
