package com.wanmait.jwtdemo.controller;

import com.wanmait.jwtdemo.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@Controller
@RequestMapping("/user")
public class UserController {

    @Resource
    private UserService userService;

    @PostMapping("/login")
    public String login(@RequestParam(name = "username") String username,
                              @RequestParam(name = "password") String password, HttpSession session, HttpServletResponse response){
        String token = userService.login(username, password);
        if(token==null){
            return "redirect:/user/login.html";
        }
        session.setAttribute("token",token);
        return "redirect:/user/index.html";
    }
}
