package mc.apps.spring.controllers;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;

@Controller
public class FrontController {
    private static final Logger logger = LogManager.getLogger(FrontController.class);

    @RequestMapping(value="/")
    public String index(@RequestParam(required=false, defaultValue="index") String page,  Model model,
                        Authentication authentication){


        model.addAttribute("title", "Spring Boot");
        String loggedin =  (authentication==null)?"":authentication.getName();
        model.addAttribute("logged", loggedin);

        logger.log(Level.INFO, "page = "+page+" - logged user : "+loggedin);
        return page;
    }

    @RequestMapping(value="/{action}")
    public String display(@PathVariable String action,  Model model, Authentication authentication){

        logger.log(Level.INFO, "action = "+action);
        //        if(action.equals("logout")) {
        //            logger.info("*********************************************");
        //            logger.info("Bye!");
        //            logger.info("*********************************************");
        //            return "redirect:/";
        //        }

        model.addAttribute("title", formatted(action));
        model.addAttribute("logged", (authentication==null)?"":authentication.getName());
        return action;
    }
    private String formatted(String page) {
        return page.substring(0,1).toUpperCase()+page.substring(1).toLowerCase();
    }
}
