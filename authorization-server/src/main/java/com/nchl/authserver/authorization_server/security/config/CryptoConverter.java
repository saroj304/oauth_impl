package com.nchl.authserver.authorization_server.security.config;


import com.nchl.authserver.authorization_server.Utility.Utilities;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Converter
public class CryptoConverter implements AttributeConverter<String, String> {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public String convertToDatabaseColumn(String arg0) {
        try {
            return Utilities.encrypt(arg0);
        } catch (Exception e) {
            logger.error(e.toString());
            throw new RuntimeException(e);
        }
    }

    @Override
    public String convertToEntityAttribute(String arg0) {
        try {
            return Utilities.decrypt(arg0);
        } catch (Exception e) {
            logger.error(e.toString());
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        CryptoConverter cryptoConverter = new CryptoConverter();
        System.out.println(cryptoConverter.convertToDatabaseColumn("00188185120"));
        System.out.println(cryptoConverter.convertToDatabaseColumn("bishnudhital@nchl.com.np"));
        System.out.println(cryptoConverter.convertToEntityAttribute("sMOFrqfokySIA1MLjmyPsw=="));
        System.out.println(cryptoConverter.convertToEntityAttribute("DZ7VEoUCz7AzQcATvKrKRw=="));
    }

}
