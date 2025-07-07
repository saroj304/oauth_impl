package com.nchl.authserver.authorization_server.Utility;



import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service("util")
public class Utilities {

//	@Value("${helpdesk.email}")
//	private String helpdeskEmail;

    private static final String CIPHER = "12345667ABCDEG";
    private static final String ALGO = "AES";
    private static final byte[] keyValue = new byte[]{'s', 't', 'b', 'j', 'c', 'S', 'B', 'u', 'W', '2', 'O', 'B', 'o',
            'r', 'S', 'u'};
    /**
     * Regex that allows alphanumeric value up to length 30
     * Avoids symbols such as ', ", ;, -, /, (, ), *, %, &, =, |, <, >.
     **/
    private static final String SECURITY_ANS_VALIDATION_REGEX = "^[^'\\\"\\\\;\\-\\/\\(\\)\\*\\%&=|<>]{1,30}$";
    private JavaMailSenderImpl mailSender;
//    private ApplicationProperties ipsApplicationProperties;
//    private UtilitiesDB utilitiesDB;

    public static boolean isNotNumberWith2Decimals(BigDecimal value) {
        try {
            if (value.compareTo(new BigDecimal("0.01")) > 0) {
                String tranAmt = value.toPlainString();
                return !tranAmt.matches("^\\s*(?=.*[1-9])\\d*(?:\\.\\d{1,2})?\\s*$");
            } else {
                return true;
            }
        } catch (Exception e) {
            log.error(e.toString());
            return true;
        }

    }

    public static boolean validateMpin(String mpin) {
        Pattern VALID_MPIN_NO_REGEX = Pattern.compile("^[0-9]{6}$");

        Matcher matcher = VALID_MPIN_NO_REGEX.matcher(mpin);
        return !matcher.find();
    }

/*    public static boolean validateEmailId(String emailStr) {
        Pattern VALID_EMAIL_ADDRESS_REGEX = Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$",
                2);
        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(emailStr);
        boolean result = matcher.find();

        if (result) {
            return EmailValidator.isValidEmail(emailStr);
        } else {
            return false;
        }
    }

    public static String jasyptEncrypt(String text) {
        try {
            PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
            encryptor.setSaltGenerator(new ZeroSaltGenerator());
            encryptor.setPoolSize(4);
            encryptor.setPassword(CIPHER);
            return encryptor.encrypt(text);
        } catch (Exception ex) {
            log.error("e: ", ex);
            return null;
        }
    }

    public static String jasyptDecrypt(String text) {
        try {

            BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
            textEncryptor.setPassword(CIPHER);
            return textEncryptor.decrypt(text);
        } catch (Exception ex) {
            log.error("e: ", ex);
            return null;
        }
    }

    public static String jasyptEncrypt(String text, String cipher) {
        try {
            PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
            encryptor.setSaltGenerator(new ZeroSaltGenerator());
            encryptor.setPoolSize(4);
            encryptor.setPasswordCharArray(cipher.toCharArray());
            encryptor.setStringOutputType("hexadecimal");
            return encryptor.encrypt(text);
        } catch (Exception ex) {
            return null;
        }
    }

    public static String jasyptDecrypt(String text, String cipher) {
        try {
            PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
            encryptor.setSaltGenerator(new ZeroSaltGenerator());
            encryptor.setPoolSize(4);
            encryptor.setPasswordCharArray(cipher.toCharArray());
            encryptor.setStringOutputType("hexadecimal");
            return encryptor.decrypt(text);
        } catch (Exception ex) {
            log.error(ex.toString());
            return null;
        }
    }*/

    public static String jasyptEncryptEncode(String data, String cipher) {
        try {
            Key key = generateKey();
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encVal = c.doFinal(data.getBytes());
            return Base64.getUrlEncoder().encodeToString(encVal);
        } catch (Exception ex) {
            log.error(ex.getMessage());
            return null;
        }
    }

    //
    public static String jasyptDecryptDecode(String encryptedData, String cipher) {
        try {
            Key key = generateKey();
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decordedValue = Base64.getUrlDecoder().decode(encryptedData);
            byte[] decValue = c.doFinal(decordedValue);
            return new String(decValue);
        } catch (Exception ex) {
            log.error(ex.getMessage());
            return null;
        }
    }

    public static String encrypt(String data) {
        if(null == data) return null;
        try {
            Key key = generateKey();
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encVal = c.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encVal);
        } catch (Exception ex) {
            // log.error(ex.toString());
            return null;
        }
    }

    public static String decrypt(String encryptedData) {
        try {
            Key key = generateKey();
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
            byte[] decValue = c.doFinal(decordedValue);
            return new String(decValue);
        } catch (Exception ex) {
            // log.error(ex.toString());
            return null;
        }
    }

   /* public static String securityAnsEncrypt(String data) {
        if (StringUtil.isEmpty(data)) {
            return null;
        }
        if (StringUtils.equals(PropertiesConfiguration.enableSecurityAnsEncrypt, "Y")) {
            return encrypt(getTrimAndLowerCaseStr(data));
        } else {
            return getTrimAndLowerCaseStr(data);
        }
    }

    public static String securityAnsDecrypt(String encryptedData) {
        if (StringUtils.equals(PropertiesConfiguration.enableSecurityAnsEncrypt, "Y")) {
            try {
                Key key = generateKey();
                Cipher c = Cipher.getInstance(ALGO);
                c.init(Cipher.DECRYPT_MODE, key);
                byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
                byte[] decValue = c.doFinal(decordedValue);
                return new String(decValue);
            } catch (Exception ex) {
                return encryptedData;
            }
        } else {
            return encryptedData;
        }
    }*/

    private static Key generateKey() throws Exception {
        return new SecretKeySpec(keyValue, ALGO);
    }


    public static void main(String[] args) throws UnsupportedEncodingException, ParseException {
//        System.out.println(jasyptEncrypt("506959", "301842"));
//        System.out.println(jasyptDecrypt("lewp8M35YKI=", "301792"));
//        String a = "{\"debitAcid\": \"bZPaxYnKyVI=\"," +
//                "  \"txnAmt\": 1000.5," +
//                "  \"vpaSystemId\": \"1901\"," +
//                "  \"beneficiaryId\": \"9841257125\"," +
//                "  \"paymentNetwork\": \"NPI\"}";
//        System.out.println(JasonWebToken.createJWT(a));

        System.out.println(findRawValueInRegex("test1@gmail.com", "^((?!\\.)[\\w._-]*[^.])@\\w+(\\.\\w+){1,2}$"));;
        System.out.println(findRawValueInRegex("riya@gmail.com", "^((?!\\.)[\\w._-]*[^.])@\\w+(\\.\\w+){1,2}$"));;
        System.out.println(matchRawValueWithRegex("riya@gmail.com", "^((?!\\.)[\\w._-]*[^.])@\\w+(\\.\\w+){1,2}$"));;
    }

    public static Date parseDate(String date) {
        try {
            return new SimpleDateFormat("yyyy-MM-dd").parse(date);
        } catch (Exception e) {
            return null;
        }
    }

/*    public static boolean validatePhoneNo(String phoneNo) {
        String mobNo = StringUtils.right(phoneNo, 8);
        Pattern VALID_PHONE_NO_REGEX = Pattern.compile("^((?!(0))[0-9]{8})$");

        Matcher matcher = VALID_PHONE_NO_REGEX.matcher(mobNo);
        System.out.println(phoneNo);
        return matcher.find();

    }*/

    public static boolean isNumber(String number) {
        // String mobNo = StringUtils.right(phoneNo, 8);
        Pattern VALID_PHONE_NO_REGEX = Pattern.compile("^[0-9]+$");

        Matcher matcher = VALID_PHONE_NO_REGEX.matcher(number);
        // System.out.println(phoneNo);
        return !matcher.find();

    }
/*
    public static boolean validateAccountNumber(String accountNumber) {
        String mobNo = StringUtils.right(accountNumber, 20);
        // Pattern VALID_ACC_NO_REGEX = Pattern.compile("^[a-z0-9]+$");
        Pattern VALID_ACC_NO_REGEX = Pattern.compile(Constant.COMMON_ACCOUNT_REGEX_PATTERN);
        Matcher matcher = VALID_ACC_NO_REGEX.matcher(mobNo);
        System.out.println(accountNumber);
        return !matcher.find();

    }*/

    public static boolean findRawValueInRegex(String raw, String regex) {
        return Pattern.compile(regex).matcher(raw).find();
    }

    public static boolean matchRawValueWithRegex(String raw, String regex) {
        return Pattern.compile(regex).matcher(raw).matches();
    }

    public static boolean isValidDate(String dateToValidate, String dateFromat) {

        if (dateToValidate == null) {
            return false;
        }
        SimpleDateFormat sdf = new SimpleDateFormat(dateFromat);
        sdf.setLenient(false);
        try {
            // if not valid, it will throw ParseException
            Date date = sdf.parse(dateToValidate);
            System.out.println(date);
        } catch (ParseException e) {
            log.error(e.toString());
            return false;
        }

        return true;
    }

    public static boolean isThisDateValid(String dateToValidate, String dateFromat) {
        if (dateToValidate == null) {
            return false;
        }
        SimpleDateFormat sdf = new SimpleDateFormat(dateFromat);
        sdf.setLenient(false);
        try {
            // if not valid, it will throw ParseException
            Date date = sdf.parse(dateToValidate);
            System.out.println(date);
        } catch (ParseException e) {
            log.error(e.toString());
            return false;
        }
        return true;
    }

    public static boolean validDatePeriod(Date fromDate, Date toDate) {
        try {
            long difference = toDate.getTime() - fromDate.getTime();
            float days = ((float) difference / (1000 * 60 * 60 * 24));
            return days <= 90;
        } catch (Exception ex) {

            return false;

        }

    }

    public static boolean validDatePeriod(LocalDateTime fromDate, LocalDateTime toDate) {
        try {
            float days = ChronoUnit.DAYS.between(fromDate, toDate);
            if (days <= 90) {
                return true;
            } else {
                return false;
            }
        } catch (Exception ex) {
            return false;
        }
    }

    public static boolean govtVoucherNumberFormetCheck(String refId) {

        Pattern Valid_voucher_number_format = Pattern.compile("^[0-9-]+$");
        Matcher matcher = Valid_voucher_number_format.matcher(refId);
        return matcher.find();
    }

    static long findDifference(String start_date, String end_date) {
        SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        long difference = 0;
        try {
            Date d1 = sdf.parse(start_date);
            Date d2 = sdf.parse(end_date);
            difference = d2.getTime() - d1.getTime();
        }
        // Catch the Exception
        catch (ParseException e) {
            log.error(e.toString());
        }
        return difference;
    }

/*    public static String getHashValue(String... strings) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (String str : strings) {
            md.update(StringUtil.defaultString(str).getBytes());
        }
        byte[] mdBytes = md.digest();
        StringBuilder hexString = new StringBuilder();
        for (byte mdByte : mdBytes) {
            hexString.append(Integer.toHexString(0xFF & mdByte));
        }
        return hexString.toString();
    }*/

    //DishHome bonus
    public static Integer getDishHomeBonusAmount(Integer amount) {
        Map<Integer, Integer> bonusMap = new HashMap<>();
//        bonusMap.put(10000, 2000);
//        bonusMap.put(9000, 1800);
//        bonusMap.put(7000, 1120);
//        bonusMap.put(6000, 900);
//        bonusMap.put(5000, 700);
//        bonusMap.put(4000, 480);
//        bonusMap.put(3000, 240);
//        bonusMap.put(2000, 120);
//        bonusMap.put(1000, 30);
//        bonusMap.put(700, 0);
//        bonusMap.put(500, 0);
//        bonusMap.put(400, 0);
//        bonusMap.put(350, 0);
        //Change as requested
        bonusMap.put(10000, 2200);
        bonusMap.put(9000, 1890);
        bonusMap.put(7000, 1400);
        bonusMap.put(6000, 1200);
        bonusMap.put(5000, 1000);
        bonusMap.put(4000, 600);
        bonusMap.put(3000, 360);
        bonusMap.put(2000, 200);
        bonusMap.put(1000, 50);
        bonusMap.put(700, 0);
        bonusMap.put(500, 0);
        bonusMap.put(400, 0);
        bonusMap.put(350, 0);

        return bonusMap.get(amount);
    }

    public static char getRandomCharacter() {
        Random random = new Random();
        return (char) (random.nextInt(26) + 'a');
    }

    public static String addRandomCharacter(String str, char ch, int position) {
        return str.substring(0, position) + ch + str.substring(position);
    }

    public static String changeDateFormat(String dateToConvert, String sourceDateFormat, String distDateFormat) {
        SimpleDateFormat sdf = new SimpleDateFormat(sourceDateFormat);
        String retrunDate = "";
        try {
            Date date = sdf.parse(dateToConvert);
            SimpleDateFormat df = new SimpleDateFormat(distDateFormat);
            retrunDate = df.format(date);
        } catch (ParseException e) {
            log.error(e.toString());

        }
        return retrunDate;
    }

    public static String changeDateFormat(String dateToConvert, String distDateFormat) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-mm-dd");
        String retrunDate = "";
        try {
            Date date = sdf.parse(dateToConvert);
            SimpleDateFormat df = new SimpleDateFormat(distDateFormat);
            retrunDate = df.format(date);
        } catch (ParseException e) {
            log.error(e.toString());
        }
        return retrunDate;
    }

    public static Date addDaysToDate(Date date, int daysToAdd) {
        // Create a Calendar instance and set it to the provided date
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);

        // Add or subtract the specified number of days
        calendar.add(Calendar.DAY_OF_MONTH, daysToAdd);

        // Get the updated date

        return calendar.getTime();
    }

    public static boolean hasAllIdenticalDigits(int number) {
        int firstDigit = number % 10;
        while (number > 0) {
            if (number % 10 != firstDigit) {
                return false;
            }
            number /= 10;
        }
        return true;
    }

/*    public static String getTrimAndLowerCaseStr(String raw) {
        return StringUtils.lowerCase(StringUtils.trim(raw));
    }*/

    public static boolean validateSecurityAnswerPattern(String raw) {
        Pattern pattern = Pattern.compile(SECURITY_ANS_VALIDATION_REGEX);
        return !pattern.matcher(raw).find();
    }

    public static String getSpacedStringFromCombinedCapitalizedWords(String raw) {
        StringBuilder sbTemp = new StringBuilder();
        StringBuilder sbResult = new StringBuilder();

        for (char c : raw.toCharArray()) {
            if (Character.isUpperCase(c)) {
                sbResult.append(sbTemp).append(" ");
                sbTemp.setLength(0);
            }
            sbTemp.append(c);
        }
        sbResult.append(sbTemp);
        return sbResult.toString();
    }
/*

    private static MobileCode getCountryCodeFromMobileNo(String mobileNo) {
        for (MobileCode countryCode : MobileCode.values()) {
            if (mobileNo.startsWith(countryCode.getCode())) {
                return countryCode;
            }
        }
        throw new IllegalArgumentException("Mobile Country code not recognized");
    }

    public static boolean validateMobileNo(String mobileNo) {
        MobileCode code = getCountryCodeFromMobileNo(mobileNo);
        return code.isValidPhoneNumber(mobileNo);
    }
*/

    public String encodePassword(String password) {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.encode(password);
    }

/*    public String generateUserPwd() {
        String SpecialChars = "!@#$*";
        String password = RandomStringUtils.randomAlphabetic(1).toUpperCase()
                + RandomStringUtils.random(1, SpecialChars) + RandomStringUtils.randomNumeric(8);
        return password.toUpperCase();
    }

    public String generateUserMpin() {
        String mpin = RandomStringUtils.randomNumeric(6);
        return mpin.toUpperCase();
    }

    public String lpad(String str, int padlength, String padvalue) {
        return StringUtils.leftPad(str, padlength, padvalue);
    }

    public String rpad(String str, int padlength, String padvalue) {
        return StringUtils.rightPad(str, padlength, padvalue);
    }*/

//	public String getLocationByIP(String ip) {
//		String address = "UNKNOWN";
//		if (StringUtils.startsWith(ip, "0:") || StringUtils.startsWith(ip, "10.")) {
//			address = "LOCAL";
//		}
//		try {
////			File database = new File(ipsApplicationProperties.getApplicationContextPath()
////					+ StartUpLoader.propertiesConfiguration.geoLocationdbFile);
//			File database=new File("");
//			// File database = new File(dbLocation);
//			DatabaseReader dbReader;
//			dbReader = new DatabaseReader.Builder(database).build();
//			InetAddress ipAddress = InetAddress.getByName(ip);
//			CityResponse response = dbReader.city(ipAddress);
//			String countryName = response.getCountry().getName();
//			String cityName = response.getCity().getName();
//			String state = response.getLeastSpecificSubdivision().getName();
//			address = cityName + " - " + state + " , " + countryName;
//			log.info("RequestFrom:" + address);
//		} catch (IOException | GeoIp2Exception e) {
//			log.error(e.getLocalizedMessage());
//		}
//		return address;
//	}

//	public String getlocationCodeIP(String ip) {
//		String locationCode = "UNKNOWN";
//		if (StringUtils.startsWith(ip, "0:") || StringUtils.startsWith(ip, "10.")) {
//			locationCode = "LOCAL";
//		}
//		try {
//			File database=new File("");

    /// /			File database = new File(ipsApplicationProperties.getApplicationContextPath()
    /// /					+ StartUpLoader.propertiesConfiguration.geoLocationdbFile);
//			// File database = new File(dbLocation);
//			DatabaseReader dbReader;
//			dbReader = new DatabaseReader.Builder(database).build();
//			InetAddress ipAddress = InetAddress.getByName(ip);
//			CityResponse response = dbReader.city(ipAddress);
//			String latitude = response.getLocation().getLatitude().toString();
//			String longitude = response.getLocation().getLongitude().toString();
//			locationCode = latitude + "-" + longitude;
//			log.info("RequestFrom:" + latitude + longitude);
//		} catch (IOException | GeoIp2Exception e) {
//			log.error(e.getLocalizedMessage());
//		}
//		return locationCode;
/*
//	}
    public String truncate(String str, int length) {
        return StringUtils.substring(str, 0, length);
    }
*/

    public String convertIsoAmount(String amount) {
        if (amount.startsWith("-")) {
            return "(" + amount.substring(1).replaceFirst("^0+(?!$)", "") + ")";
        } else {
            return amount.substring(1).replaceFirst("^0+(?!$)", "");
        }
    }

/*    public boolean isStrongPassword(String password) {
        boolean result = false;
        final Pattern pattern;
        final Matcher matcher;

        String PASSWORD_PATTERN = PropertiesConfiguration.PasswordPattern;
        pattern = Pattern.compile(PASSWORD_PATTERN);
        matcher = pattern.matcher(password);
        return matcher.matches();
    }*/

    public <T> T nvl(T arg0, T arg1) {
        return (arg0 == null || arg0.equals("null")) ? arg1 : arg0;
    }

    public String getCurrentDateTime(String dateTimeFormat) {
        String result = "";
        DateFormat dateFormat = new SimpleDateFormat(dateTimeFormat);
        Date date = new Date();
        result = dateFormat.format(date);
        return result;
    }

    public String convertDateFormat(String dateStr, String dateFormat, String newDateFormat) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(dateFormat);
            Date date = sdf.parse(dateStr);
            sdf = new SimpleDateFormat(newDateFormat);
            dateStr = sdf.format(date);
        } catch (Exception ex) {
            System.out.println("Date Convert Exception: " + ex);
        }
        return dateStr;
    }

    public String convertDateFormat(Date date, String newDateFormat) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(newDateFormat);
            return sdf.format(date);
        } catch (Exception ex) {
            System.out.println("Date Convert Exception: " + ex);
            throw new RuntimeException(ex);
        }
    }


    public Date getDate(String dateStr, String dateFormat) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(dateFormat);
            return sdf.parse(dateStr);
        } catch (Exception ex) {
            throw new RuntimeException("Invalid Date Format");
        }
    }

    public String dateToString(Date inDate, String dateFormat) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(dateFormat);
            return sdf.format(inDate);
        } catch (Exception ex) {
            throw new RuntimeException("Invalid Date Format");
        }
    }

    public Date addDaysToDate(int noOfDays) {
        Date dt = new Date();
        Calendar c = Calendar.getInstance();
        c.setTime(dt);
        c.add(Calendar.DATE, noOfDays);
        dt = c.getTime();
        return dt;
    }

/*    public String getRandomkey(int length) {
        return RandomStringUtils.randomNumeric(length);
    }

    public String getRandomAlphaNumerickey(int length) {
        return RandomStringUtils.randomAlphanumeric(length);
    }*/

    public boolean isValidCreditCard(String str) {

        int[] ints = new int[str.length()];
        for (int i = 0; i < str.length(); i++) {
            ints[i] = Integer.parseInt(str.substring(i, i + 1));
        }
        for (int i = ints.length - 2; i >= 0; i = i - 2) {
            int j = ints[i];
            j = j * 2;
            if (j > 9) {
                j = j % 10 + 1;
            }
            ints[i] = j;
        }
        int sum = 0;
        for (int anInt : ints) {
            sum += anInt;
        }
        return sum % 10 == 0;
    }

/*    public boolean isR2pTxnAmountGreater(BigDecimal amount) {
        return amount.compareTo(PropertiesConfiguration.r2pTxnAmountUpperLimit) == 1;

    }

    public boolean validateVirtualPrivateAddress(String virtualPrivateAddress) {


        boolean result = false;
        final Pattern pattern;
        final Matcher matcher;
        String VPA_PATTERN = PropertiesConfiguration.VPAPattern;
//		"((?=.*\\d)(?=.*[A-Z])(?=.*[!@#$*]).{8,20})";
        pattern = Pattern.compile(VPA_PATTERN);
        matcher = pattern.matcher(virtualPrivateAddress);
        result = matcher.matches();
        return result;
    }*/

    public String extractTextBetweenCurlyBraces(String input) {
        Pattern pattern = Pattern.compile("\\{(.*?)}");
        Matcher matcher = pattern.matcher(input);

        if (matcher.find()) {
            return matcher.group(1); // Extract text between curly braces
        } else {
            return ""; // Return empty string if no match is found
        }
    }
/*
    public void printOtpInDevEnvOnly(String otp) {
        if (!ipsApplicationProperties.getApplicationProfile().isEmpty()
                && Constant.APPLICATION_PROFILE.equals(decrypt(ipsApplicationProperties.getApplicationProfile()))
                && !"live".equals(ipsApplicationProperties.getApplicationProfile())
        ) {
            log.error("⚠️⚠️⚠️⚠️ WARNING:: OTP Value (For testing purposes in DEV only):-> [ {} ] ⚠️⚠️⚠️", otp);
        }
    }

    public String generateStr(int i) {
        return i < 0 ? "" : generateStr((i / 26) - 1) + (char) (65 + i % 26);
    }

    public String getValidationTraceId() {
        Random random = new Random();
        return getCurrentDateTime("yyMMdd")
                + StringUtils.leftPad(String.valueOf(utilitiesDB.getSequenceId(DbSequence.QR_VALIDATION_PARSE_SEQUENCE)), 10, "0")
                + generateStr((random.nextInt() * (17485 - 602)) + 807);
    }

    @Autowired
    private void setIpsApplicationProperties(final ApplicationProperties ipsApplicationProperties) {
        this.ipsApplicationProperties = ipsApplicationProperties;
    }

    @Autowired
    private void setUtilitiesDB(final UtilitiesDB utilitiesDB) {
        this.utilitiesDB = utilitiesDB;
    }

    public String getMobileNumberWithCountryCode(String countryCode, String mobileNo) {
        return StringUtils.join(MobileCode.fromCode(countryCode).getCode(), "-", mobileNo);
    }*/

    public static long generateSecureRandomNumber() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyMMddHHmmss");
        String timestamp = dateFormat.format(new Date());
        SecureRandom secureRandom = new SecureRandom();
        String randomDigits = String.format("%03d", secureRandom.nextInt(1000)); // Ensures 3 digits
        String combined = timestamp + randomDigits;
        String lastEightDigits = combined.substring(combined.length() - 8);
        return Integer.parseInt(lastEightDigits);
    }

}



