package com.example.labactivity.user;

import com.example.labactivity.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.repository.query.Param;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.Optional;

@Controller
public class UserController {
    @Autowired
    private UserRepository userRepo;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserServices userServices;

    @GetMapping("/")
    public String viewHomePage() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    public String login(Model model, @Param("error" ) final Optional<String> error) {
        model.addAttribute("user", new User());
        error.ifPresent( e ->  model.addAttribute("error", e));
        return "login";
    }

    @GetMapping("/forgot-password")
    public String forgotPassword(Model model) {
        model.addAttribute("user", new User());
        return "forgot-password";
    }

    @PostMapping("/verify-forgot-email")
    public String verifyForgotEmail(User user) throws MessagingException, UnsupportedEncodingException {
        System.out.println(user.getEmail());
        User userFormDB = userRepo.findUserByEmail(user.getEmail());
        if ( userFormDB != null) {
            userFormDB.setOtp(userServices.generateOneTimePassword(userFormDB));
            userRepo.save(userFormDB);
            return "redirect:/otp-change-password?email=" + userFormDB.getEmail();
        } else
            return "redirect:/forgot-password?error=true";
    }

    @GetMapping("/otp-change-password")
    public String verifyChangePassword (Model model, @Param("email") String email) {
        User user = new User();
        user.setEmail(email);
        model.addAttribute("code", userRepo.findUserByEmail(email).getOtp());
        model.addAttribute("method", "forgot-password");
        model.addAttribute("user", user);
        model.addAttribute("message", "Check your email for code to verify your identify");
        return "otp";
    }

    @GetMapping("/change-password")
    public String changePassword (Model model, @Param("otp") String otp, @Param("email") String email) {
        model.addAttribute("user", new User());
        model.addAttribute("email", email);
        model.addAttribute("otp", otp);
        return "change-password";
    }

    @PostMapping("process-change-password")
    public String verifyChangePassword(User user, @Param("otp") String otp, @Param("email") String email) {
        User userFromDB = userRepo.findUserByEmail(email);

        boolean verifyOTP2nd = BCrypt.checkpw(otp, userFromDB.getOtp());
        if (verifyOTP2nd) {
            if(!userServices.passwordStrengthValidate(user.getPassword()))
                return "redirect:/change-password?password=true" + "&otp=" + otp + "&email=" + email;

            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            String encodedPassword = passwordEncoder.encode(user.getPassword());
            userFromDB.setPassword(encodedPassword);
            userRepo.save(userFromDB);

            return "redirect:/login?changepass=true";
        } else {
            return "redirect:/change-password?token=true";
        }

    }

    @GetMapping("/dashboard")
    public String president (Model model, HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(auth.getAuthorities());
        String name = userRepo.findUserByEmail(auth.getName()).getFullName();
        model.addAttribute("name", name);

        if (request.isUserInRole("ROLE_PRESIDENT"))
            return "president";
        else if (request.isUserInRole("ROLE_DEAN"))
            return "dean";
        else if (request.isUserInRole("ROLE_STUDENT"))
            return "student";
        return "redirect:/login";
    }


    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/process_register")
    public String processRegister(Model model, User user) throws MessagingException, UnsupportedEncodingException {
        String param = "";
        if(userRepo.findUserByEmail(user.getEmail()) != null)
            param += "&email=true";
        if(userRepo.findUserByFullName(user.getFullName()) != null)
            param += "&name=true";
        if(!userServices.passwordStrengthValidate(user.getPassword()))
            param += "&password=true";
        if(param.length()>=1)
            return "redirect:/register?error=true"+param;

        System.out.println(user.getPassword());
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        model.addAttribute("message", "Check your email for code to verify your email");
        model.addAttribute("code", userServices.generateOneTimePassword(user));
        model.addAttribute("method", "verify-email");
        model.addAttribute("user", user);
        return "otp";
    }
    @GetMapping("/two-factor-auth")
    public String twoFactorAuth(Model model, @Param("email") String email){
        model.addAttribute("message", "2 Factor Authentication using Email.");
        model.addAttribute("code", userRepo.findUserByEmail(email).getOtp());
        model.addAttribute("method", "2fa");
        model.addAttribute("user", new User());

        return "otp";
    }

    @PostMapping("/validate-otp")
    public String validateOtp (Model model, User user, @Param("otp") String otp, @Param("method") String method, @Param("code") String code) {
        boolean verifyOTP = BCrypt.checkpw(otp, code);
        if(verifyOTP && method.equals("2fa")) {
            userServices.grantUserRole();
            return "redirect:/";
        } else if (verifyOTP && method.equals("verify-email")) {
            user.setOtpEnabled(true);
            user.setEnabled(true);
            user.setRole(roleRepository.findRoleByName("ROLE_STUDENT"));
            userRepo.save(user);
            return "redirect:/login?email=true";
        } else if (verifyOTP && method.equals("forgot-password")){
            return "redirect:/change-password?otp=" + otp + "&email=" +user.getEmail();
        } else {
            model.addAttribute("code", code);
            model.addAttribute("method", method);
            model.addAttribute("user", user);
            model.addAttribute("error", true);
            return "otp";
        }
    }
}
