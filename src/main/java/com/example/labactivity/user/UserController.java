package com.example.labactivity.user;

import com.example.labactivity.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.repository.query.Param;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
        error.ifPresent( e ->  model.addAttribute("error", e));
        return "login";
    }

    @GetMapping("/otp")
    public String otp(Model model, @Param("error") boolean error) throws MessagingException, UnsupportedEncodingException {

        if(error) {
            model.addAttribute("error", "INVALID CODE");
        } else {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            System.out.println(auth.getAuthorities());
            User user = userRepo.findUserByEmail(auth.getName());
            userServices.generateOneTimePassword(user);
        }
        return "otp";
    }

    @PostMapping("/validate-otp")
    public String validateOtp (@Param("otp") String otp) {
        if(userServices.verifyOTP(otp)) {
            userServices.grantUserRole();
            return "redirect:/";
        }
        else {
            return "redirect:/otp?error=true";
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
        else if (request.isUserInRole("ROLE_PROFESSOR"))
            return "professor";
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
    public String processRegister(@Param("name") String name, @Param("email") String email, @Param("password") String password) {
        System.out.println(email);
        User user = new User();
        user.setFullName(name);
        user.setEmail(email);
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String encodedPassword = passwordEncoder.encode(password);
        user.setPassword(encodedPassword);
        user.setOtpEnabled(true);
        user.setRole(roleRepository.findRoleByName("ROLE_STUDENT"));
        userRepo.save(user);
        return "redirect:/login?success=registration";
    }

}
