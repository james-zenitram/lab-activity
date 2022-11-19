package com.example.labactivity.user;

import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.UnsupportedEncodingException;
import java.util.Date;

@Service
@Transactional
public class UserServices {
    @Autowired
    UserRepository userRepo;
    @Autowired
    JavaMailSender mailSender;
    @Autowired
    PasswordEncoder passwordEncoder;

    public void generateOneTimePassword(User user)
            throws UnsupportedEncodingException, MessagingException {
        String OTP = RandomStringUtils.randomNumeric(6);
        String encodedOTP = passwordEncoder.encode(OTP);

        user.setOtp(encodedOTP);
        user.setOtpRequestedTime(new Date());

        userRepo.save(user);
        sendOTPEmail(user, OTP);
    }

    public void sendOTPEmail(User user, String OTP) throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom("contact@shopme.com", "Shopme Support");
        helper.setTo(user.getEmail());

        String subject = "Here's your One Time Password (OTP) - Expire in 5 minutes!";

        String content = "<p>Hello " + user.getFullName() + "</p>"
                + "<p>For security reason, you're required to use the following "
                + "One Time Password to login:</p>"
                + "<p><b>" + OTP + "</b></p>"
                + "<br>"
                + "<p>Note: this OTP is set to expire in 5 minutes.</p>";

        helper.setSubject(subject);

        helper.setText(content, true);

        mailSender.send(message);
    }

    public void clearOTP(User user) {
        user.setOtp(null);
        user.setOtpRequestedTime(null);
        userRepo.save(user);
    }
}
