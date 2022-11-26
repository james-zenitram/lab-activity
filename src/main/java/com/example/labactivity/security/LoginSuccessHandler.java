package com.example.labactivity.security;

import com.example.labactivity.user.User;
import com.example.labactivity.user.UserRepository;
import com.example.labactivity.user.UserServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.mail.MessagingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    UserRepository userRepository;

    @Autowired
    UserServices userServices;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findUserByEmail(userDetails.getUsername());
        if (user.getOtpEnabled()) {
            try {
                user.setOtp(userServices.generateOneTimePassword(user));
                userRepository.save(user);
                response.sendRedirect("/two-factor-auth?email="+user.getEmail());
            } catch (MessagingException e) {
                throw new RuntimeException(e);
            }
        }
        else
            response.sendRedirect("/");
    }
}
