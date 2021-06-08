package mc.apps.spring.controllers;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class FrontController {
    private static final Logger logger = LogManager.getLogger(FrontController.class);

    @RequestMapping(value="/")
    public String index(@RequestParam(required=false, defaultValue="index") String page,  Model model){
        logger.log(Level.INFO, "page = "+page);

        model.addAttribute("title", "Spring Boot");
        return page;
    }

    @RequestMapping(value="/{action}")
    public String display(@PathVariable String action,  Model model){
        logger.log(Level.INFO, "action = "+action);
        model.addAttribute("title", formatted(action));
        return action;
    }

    private String formatted(String page) {
        return page.substring(0,1).toUpperCase()+page.substring(1).toLowerCase();
    }
}
