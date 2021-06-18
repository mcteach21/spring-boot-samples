package mc.apps.spring.controllers;

import mc.apps.spring.model.User;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;

@Controller
public class FrontController {
    private static final Logger logger = LogManager.getLogger(FrontController.class);
    private static final String DEFAULT_PATH = "/";

//    @RequestMapping(value="/")
//    public String index(@RequestParam(required=false, defaultValue="index") String page,  Model model, Authentication authentication){
//
//        model.addAttribute("title", "Spring Boot");;
//        model.addAttribute("logged", (authentication==null)?"":authentication.getName());
//        model.addAttribute("user", new User());
//        return page;
//    }

    @RequestMapping(value={"/","/{action}"})
    public String display(@PathVariable(required = false) String action,  Model model, Authentication authentication){

        String page = (action==null)?"index":action;

        logger.log(Level.INFO, "****************************************");
        logger.log(Level.INFO, "page = "+page);
        logger.log(Level.INFO, "****************************************");

        model.addAttribute("title", formatted(page));
        model.addAttribute("logged", (authentication==null)?"":authentication.getName());
        model.addAttribute("user", new User());

        return page;
    }


    @PostMapping(value="/{action}")
    public String post(@PathVariable String action, @ModelAttribute Object object){
        logger.log(Level.INFO, "action = "+action);
        switch (action){
            case "signup":
//                User user = (User)object;
                logger.log(Level.INFO, "User = "+object.getClass().getSimpleName());
                break;
            default:
                break;
        }

        return "redirect:"+DEFAULT_PATH;
    }
    private String formatted(String page) {
        return page.substring(0,1).toUpperCase()+page.substring(1).toLowerCase();
    }


}
