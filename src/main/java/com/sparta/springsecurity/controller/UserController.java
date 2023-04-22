package com.sparta.springsecurity.controller;

import com.sparta.springsecurity.dto.SignupRequestDto;
import com.sparta.springsecurity.entity.User;
import com.sparta.springsecurity.entity.UserRoleEnum;
import com.sparta.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    // ADMIN_TOKEN
    private static final String ADMIN_TOKEN = "AAABnvxRVklrnYxKZ0aHgTBcXukeZygoC";

    @GetMapping("/signup")
    public ModelAndView signupPage() {
        return new ModelAndView("signup");
    }

    @GetMapping("/login-page")
    public ModelAndView loginPage() {
        return new ModelAndView("login");
    }

    @PostMapping("/signup")
    public String signup(SignupRequestDto signupRequestDto) {

        String username = signupRequestDto.getUsername();
        String password = passwordEncoder.encode(signupRequestDto.getPassword());

        // 회원 중복 확인
        Optional<User> found = userRepository.findByUsername(username);
        if (found.isPresent()) {
            throw new IllegalArgumentException("중복된 사용자가 존재합니다.");
        }

        // 사용자 ROLE 확인
        UserRoleEnum role = UserRoleEnum.USER;
        if (signupRequestDto.isAdmin()) {
            if (!signupRequestDto.getAdminToken().equals(ADMIN_TOKEN)) {
                throw new IllegalArgumentException("관리자 암호가 틀려 등록이 불가능합니다.");
            }
            role = UserRoleEnum.ADMIN;
        }

        User user = new User(username, password, role);
        userRepository.save(user);

        return "redirect:/api/user/login-page";
    }

    // @AuthenticationPrincipal 의 역할
    // Authentication 인증 객체의 Principle 부분의 값을 가져온다.
    // CustomSecurityFilter 에서 인증 객체를 만들 때,
    // UsernamePasswordAuthenticationToken 의 principle 부분에 UserDetails를 넣어줬기 때문에 파라미터로 받아올 수 있다.
    @PostMapping("/login")
    public String login(@AuthenticationPrincipal UserDetails userDetails) {
        System.out.println("*********************************************************");
        System.out.println("UserController.login");
        System.out.println("userDetails.getUsername() = " + userDetails.getUsername());
        System.out.println("*********************************************************");

        return "redirect:/api/user/login-page";
    }

    @PostMapping("/forbidden")
    public ModelAndView forbidden() {
        return new ModelAndView("forbidden");
    }
}