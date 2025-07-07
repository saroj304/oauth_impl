package com.nchl.authserver.authorization_server.security;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

@Service("customPasswordEncoder")
public class CustomPasswordEncoder {

    public String encode(CharSequence rawPassword) {
        String passwordString = rawPassword.toString();
        String hashed = BCrypt.hashpw(passwordString, BCrypt.gensalt(10));
        return hashed;
    }

    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        String passwordString = rawPassword.toString();
        passwordString = passwordString.substring(3);
        return BCrypt.checkpw(passwordString, encodedPassword);
    }

}
