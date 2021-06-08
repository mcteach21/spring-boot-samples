package mc.apps.spring.controllers;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class MyErrorController implements ErrorController {

    @RequestMapping({"/error","/login-error"})
    public String handleError(Model model) {
        model.addAttribute("error","url non valide!");
        return "error";
    }

//    @Override
//    public String getErrorPath() {
//        return null;
//    }
}
