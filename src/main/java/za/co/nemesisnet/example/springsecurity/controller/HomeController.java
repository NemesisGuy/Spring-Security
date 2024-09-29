package za.co.nemesisnet.example.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "home";  // This should match a template named home.html
    }

   /* @GetMapping("/login")
    public String login() {
        return "login";  // This should match a template named login.html
    }
*/
/*    @GetMapping("/logout-success")
    public String logoutSuccess() {
        return "logout-success";  // A simple logout success page template
    }*/
}
