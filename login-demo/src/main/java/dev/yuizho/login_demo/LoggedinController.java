package dev.yuizho.login_demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/loggedin")
public class LoggedinController {
    @GetMapping
    String loggedin(Model model) {
        return "index";
    }
}
