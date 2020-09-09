package com.salt.keybase.controllers;

import javax.annotation.security.RolesAllowed;

import com.salt.keybase.dataobjects.Challenge;
import com.salt.keybase.utils.ChallengeUtils;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
/**
 * @author Teun Westbroek
 */
@Controller
public class MainController {

	@RequestMapping("/")
	public String root() {
		return "redirect:/index";
	}

	@RequestMapping("/index")
	public String index() {
		return "index";
	}

	@RequestMapping("/challenge")
	public String getChallenge(Model model) throws Exception {
		Challenge challenge=ChallengeUtils.generateChallenge();
		model.addAttribute("challenge", challenge.getEncryptedChallenge());
		model.addAttribute("iv", challenge.getEncodedIV());
		return "challenge";
	}
	
	@RequestMapping("/user/index")
	@RolesAllowed("USER")
	public String userIndex() {
		return "user/index";
	}
}