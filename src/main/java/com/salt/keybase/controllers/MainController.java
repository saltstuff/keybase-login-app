package com.salt.keybase.controllers;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import javax.annotation.security.RolesAllowed;

import com.salt.keybase.dataobjects.Challenge;
import com.salt.keybase.utils.AESUtils;

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
		String timeinmillis=Long.toString(new Date().getTime());
		byte[] iv=AESUtils.getInstance().getRandomNonce();
		String encryptedMessage=Base64.getEncoder().encodeToString(AESUtils.getInstance().encrypt(timeinmillis.getBytes(StandardCharsets.UTF_8), iv));
		
		String encodedIv=Base64.getEncoder().encodeToString(iv);
		
		Challenge unsignedChallenge=new Challenge(encryptedMessage,encodedIv);
		model.addAttribute("unsignedchallenge", unsignedChallenge.toString());
		return "challenge";
	}
	
	@RequestMapping("/user/index")
	@RolesAllowed("USER")
	public String userIndex() {
		return "user/index";
	}
}