package com.example.labactivity.user;


import com.example.labactivity.Role;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "users")
public class User {

    private static final long OTP_VALID_DURATION = 5 * 60 * 1000;   // 5 minutes

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", nullable = false)
    private Integer id;

    @Column(name = "email", nullable = false, length = 45)
    private String email;

    @Column(name = "full_name", nullable = false, length = 45)
    private String fullName;

    @Column(name = "password", nullable = false, length = 64)
    private String password;

    @Column(name = "enabled")
    private Boolean enabled;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role")
    private Role role;

    @Column(name = "otp_enabled", nullable = false)
    private Boolean otpEnabled;

    @Column(name = "otp", length = 6)
    private String otp;

    @Column(name = "otp_requested_time")
    private Date otpRequestedTime;

    public Date getOtpRequestedTime() {
        return otpRequestedTime;
    }

    public boolean isOtpExpired() {
        if (this.getOtp() == null) {
            return false;
        }

        long currentTimeInMillis = System.currentTimeMillis();
        long otpRequestedTimeInMillis = this.otpRequestedTime.getTime();

        if (otpRequestedTimeInMillis + OTP_VALID_DURATION < currentTimeInMillis) {
            // OTP expires
            return false;
        }

        return true;
    }

    public void setOtpRequestedTime(Date otpRequestedTime) {
        this.otpRequestedTime = otpRequestedTime;
    }

    public String getOtp() {
        return otp;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }

    public Boolean getOtpEnabled() {
        return otpEnabled;
    }

    public void setOtpEnabled(Boolean otpEnabled) {
        this.otpEnabled = otpEnabled;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

}