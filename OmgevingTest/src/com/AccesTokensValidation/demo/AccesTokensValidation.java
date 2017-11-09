package com.AccesTokensValidation.demo;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.Date;
import java.util.Enumeration;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;


import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@WebServlet("/AccesTokensValidation")
public class AccesTokensValidation extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss");
	
    public AccesTokensValidation() {
        super();
        // TODO Auto-generated constructor stub
    }
    
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		//-------------------------------------------------------
		//---[generate and validate application access tokens]---
		//-------------------------------------------------------
		PrintWriter out = response.getWriter();
		
//--------------------------------------------	
//--------[Genereren TokenObject]-------------
//--------------------------------------------
		//aanmaken van het tokenobject
		JSONObject objToken = new JSONObject();
		
//[TEST:zelf een id voor mijn account server gebruikt]issuer-id van mijn account server
		//[TEDOEN] uitzoeken hoe je aan de accountserver-id komt
		objToken.put("iss", "my-account-server");
		
//[KLAAR]seconden sinds unix tijdperk vanaf wanneer het token als geldig moet worden beschouwd
		long currentTimestamp = System.currentTimeMillis() / 1000;
		objToken.put("iat",currentTimestamp);
	
//[KLAAR]seconden sinds unix tijdperk tot wanneer het token als geldig wordt beschouwd (zoals beschreven bij TTN + 10.000)
		long validUntilTimestamp = currentTimestamp + (10000);
		objToken.put("exp", validUntilTimestamp);

//[TEST:zelf de app-id genereren]de lijst met entiteiten waarop dit token geldig is
		//Aanmaken van nieuwe array: voor de scope 
		JSONArray arrayScope = new JSONArray();
		//[TEDOEN]App-id ophalen van de applicatie(s) welke bij de gegeven key hoort
		String app_id = "guard-test";
		arrayScope.add("apps:" + app_id);
		//Deze array toevoegen aan het tokenObject
		objToken.put("scope", arrayScope);
		
//[TEST:Zelf de rechten bepaald] een object dat app-id toewijst aan de respectieve rechten die dit token heeft voor die app
		//JSON-array aanmaken voor "foo" met daarin de rechten voor de app
        JSONArray list = new JSONArray();
        //[TEDOEN]in de database ophalen welke rechten bij de gegven Key hoort 
        String rechtenSettings 	= "niet";
        String rechtenMessages 	= "wel";
        String rechtenDevices 	= "wel";
        if(rechtenSettings.equals("wel")) {list.add("Settings");};
        if(rechtenMessages.equals("wel")) {list.add("Devices");};
        if(rechtenDevices.equals("wel")) {list.add("messages:up:r"); list.add("messages:down:w");};
        //Nieuw JSON object aanmaken voor app-id(key) met daarin de array met rechten
        JSONObject objFoo = new JSONObject();
        //de array toevoegen aan het object "foo"
        objFoo.put(app_id, list);
        //Het "foo" object toevoegen aan het objectToken 
        objToken.put("apps",objFoo);
        
        //Print het object ter controle
        out.print(objToken);
//---------------------------------------------------------	
     
	    
	    	
		//A public-private key pair to sign the JWTs
		
		//An endpoint where the handler can fetch the public key.
		
		//JWTs that are signed using the private key, and have claims that adhere to the correct schema.
		//out.println("Test");
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		PrintWriter out = response.getWriter();
		Map headers = getHeadersInfo(request);
		//Ophalen van de gegevens uit de header en vervolgens omzetten naar variabelen
		String id = (String) headers.get("id"); 
		String name = (String) headers.get("name");
		String euis = (String) headers.get("euis"); //16 char
		String created = (String) headers.get("created");
		String rights = (String) headers.get("rights"); 
		String collaborators = (String) headers.get("collaborators");
		String access_keys = (String) headers.get("access_keys"); 
		String deleted = (String) headers.get("deleted");
		
		String auth = (String) headers.get("authorization");
		String key = auth.substring(3,auth.length());
		String api_Key = "ttn-account-v2.AsPgKrlBzptbiaXEtOsvX8qnvTHEC4GZPQlKlxKdWbg";
		
		//Check of de apiKey klopt anders mag er niks gebeuren
		if(key.trim().equals(api_Key)) {
			//Status 200 OK
			Integer foutenInPost = 0;
			response.setStatus(HttpServletResponse.SC_OK);
			out.println("<h1>POST</h1>");
			out.println("<h3>HeaderFields</h3>");
//-[KLAAR]--------------------------------------------------------------------------------	
			out.println("id:");
				if(id != null && id !="") {
					List<String> lijstMetId = Arrays.asList(id.split("\\s*,\\s*"));
					if(lijstMetId.size() >= 2) {
						out.println("<b>Het inputveld id accepteerd maar 1 waarde!</b>"); 
						foutenInPost += 1;
					}else {
						out.println(id);
					}	
				}else { 
					out.println("<b>Veld id is niet ingevuld!</b>");
					foutenInPost += 1;
				}
//-[KLAAR]--------------------------------------------------------------------------------				
			out.println("<br>name");
			if(name != null && name !="") {
				List<String> lijstMetNaam = Arrays.asList(name.split("\\s*,\\s*"));
				if(lijstMetNaam.size() >= 2) {
					out.println("<b>Het inputveld name accepteerd maar 1 waarde!</b>"); 
					foutenInPost += 1;
				}else {
					out.println(name);
				}	
			}else {
				out.println("<b>Veld name is niet ingevuld!</b>");
				foutenInPost += 1; 
			}
//-[KLAAR]--------------------------------------------------------------------------------					
			out.println("<br>euis:");
			if(euis != null && euis !="") {
				List<String> lijstMetEuis = Arrays.asList(euis.split("\\s*,\\s*"));
				Integer counterEuis = 0;
				Integer foutenInEuis = 0;
				while(counterEuis < lijstMetEuis.size()) {	
					String Euis = lijstMetEuis.get(counterEuis);
					//check of het getal wel 16 tekens lang is 
					if(Euis.length() == 16) {
						//Check of het een hexadecimaal getal is
						try{
						     Long.parseUnsignedLong(Euis, 16);
						 }
						 catch(NumberFormatException nfe){
						    out.println("<b>Het " + (counterEuis+1) + "e input veld van euis is geen Hexadecimaal getal!</b>");
						    foutenInPost += 1;
						    foutenInEuis += 1;
						 }
					}else {
						out.println("<b>Het " + (counterEuis+1) + "e input veld van euis is geen 16 tekens lang! (op dit moment is deze: " + Euis.length() + ")</b>");
						foutenInPost += 1;
						foutenInEuis += 1;
					}
					counterEuis +=1;
				}
				//als er geen fouten zitten in de while loop dan klopt de input. Zo wel dan worden deze fouten al in de while loop gegenereerd
				if(foutenInEuis == 0) {
					out.println(lijstMetEuis);
				}
			}else{
				out.println("<b>Het veld euis is niet ingevuld!</b>");
				foutenInPost += 1;
			}
//-[KLAAR]--------------------------------------------------------------------------------	
			out.println("<br>created:");
			if(created != null && created !="") {
				out.println("<b>Dit veld moet leeg blijven (created wordt gegenereerd!)</b>");
				foutenInPost += 1;
			}else {
				Timestamp huidigeTijd = new Timestamp(System.currentTimeMillis());
				created = (sdf.format(huidigeTijd));
				out.println(created);
			}
//-[KLAAR]--------------------------------------------------------------------------------	
			out.println("<br>rights:");
			//check of het veld niet leeg is
			if(rights != null && rights !=" ") {
				//Input van rights splitsen naar een list
				List<String> lijstMetRechten = Arrays.asList(rights.split("\\s*,\\s*"));
				//Check of er niet meer dan 3 rechten worden toegevoegd
				if(lijstMetRechten.size() >= 4) {
					out.println("<b>Er kunnen maximaal 3 rechten meegegeven worden!</b>");
					foutenInPost +=1;
				}else {
					//Kijken of de lijst met rechten voldoet aan de eisen.
					Integer counterRechten = 0;
					Integer foutenInRechten = 0;
					String settingsStatus = "UIT";
					String devicesStatus = "UIT";
					String messagesStatus = "UIT";
					while(counterRechten < lijstMetRechten.size()) {
						String rechten = lijstMetRechten.get(counterRechten);
						//Check of de input wel voldoet
						if(rechten.equals("settings") || rechten.equals("devices") || rechten.equals("messages")) {
							//Check of de rechten niet 2 keer worden gebruikt
							if(rechten.equals("settings") && settingsStatus.equals("UIT")) {
								settingsStatus = "AAN";
							}else if(rechten.equals("settings") && settingsStatus.equals("AAN")){
								out.println("<b><b>Het " + (counterRechten+1) + "e input veld van rights: 'settings' mag maar 1 keer worden gedefinieerd!</b>");
								foutenInPost += 1;
								foutenInRechten += 1;
							}
							if(rechten.equals("devices") && devicesStatus.equals("UIT")) {
								devicesStatus = "AAN";
							}else if(rechten.equals("devices") && devicesStatus.equals("AAN")){
								out.println("<b>Het " + (counterRechten+1) + "e input veld van rights: 'devices' mag maar 1 keer worden gedefinieerd!</b>");
								foutenInPost += 1;
								foutenInRechten += 1;
							}
							if(rechten.equals("messages") && messagesStatus.equals("UIT")) {
								messagesStatus = "AAN";
							}else if(rechten.equals("messages") && messagesStatus.equals("AAN")){
								out.println("<b>Het " + (counterRechten+1) + "e input veld van rights: 'messages' mag maar 1 keer worden gedefinieerd!</b>");
								foutenInPost += 1;
								foutenInRechten += 1;
							}
						}else {
							out.println("<b>Het " + (counterRechten+1) + "e input veld van rights voldoet niet aan de eisen! (accepteerd alleen 'settings', 'devices' of 'messages')</b>");
							foutenInPost += 1;
							foutenInRechten += 1;
						}
						counterRechten += 1;		
						}
						//als er geen fouten zitten in de while loop dan voldoet de post aan alle eisen
						if(foutenInRechten == 0) {
							out.println(lijstMetRechten);
						}
					}	
			}else {
				out.println("<b>Het veld rights is niet ingevuld!</b>");
				foutenInPost += 1;
			}
			
//---------------------------------------------------------------------------------				
			out.println("<br></b>collaborators:");
			if(collaborators != null && collaborators !="") {
				List<String> lijstMetCollaborators = Arrays.asList(collaborators.split("\\s*,\\s*"));
				Integer counterCollaborators = 0;
				while(counterCollaborators < lijstMetCollaborators.size()) {
					
					counterCollaborators += 1;
				}
			}else { 
				out.println("<b>Veld collaborators is niet ingevuld!</b>");
				foutenInPost += 1;
			}
//---------------------------------------------------------------------------------	
			out.println("<br><access_keys:");
			if(access_keys != null && access_keys !="") {
				List<String> lijstMetAccessKeys = Arrays.asList(access_keys.split("\\s*,\\s*"));
				if(lijstMetAccessKeys.size() >= 2) {
					out.println("<b>Het inputveld acces_keys accepteerd maar 1 waarde!</b>"); 
					foutenInPost += 1;
				}else {
					out.println(deleted);
				}	
			}else { 
				out.println("<b>Veld access_keys is niet ingevuld!</b>");
				foutenInPost += 1;
			}
//-[KLAAR]--------------------------------------------------------------------------------	
			out.println("<br>deleted:");
			if(deleted != null && deleted !="") {
				List<String> lijstMetDeleted = Arrays.asList(deleted.split("\\s*,\\s*"));
				//Check of niet meer headervelden met deleted zijn
				if(lijstMetDeleted.size() >= 2) {
					out.println("<b>Het inputveld deleted accepteerd maar 1 waarde!</b>"); 
					foutenInPost += 1;
				}else {
					//ophalen van de eerste/enige waarde
					String lijstMetDeletedDate = lijstMetDeleted.get(0);
					String[] arrayLijstMetDeletedDate = lijstMetDeletedDate.split(Pattern.quote("."));
					//Check of het format van de input klopt
					if(arrayLijstMetDeletedDate.length == 6) {
						//Check of de inhoud van het format valid is
						try {
							//aanmaken van formaat datum
							SimpleDateFormat simpleD = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss");
							//de input vervormen naar een date met bovenstaand formaat
							Date d = (simpleD.parse(lijstMetDeletedDate));
							//Print de correcte datum
							out.println(simpleD.format(d));
						} catch (ParseException e) {
							out.println("<b>In het veld deleted klopt de inhoud van de datum niet! De datum wordt verwacht in het volgende format:\"yyyy.MM.dd.HH.mm.ss\"</b>");
							foutenInPost += 1;
						}
					}else {
						out.println("<b>In het veld deleted klopt de notatie niet! De datum wordt verwacht in het volgende format:\"yyyy.MM.dd.HH.mm.ss\"</b>"); 
						foutenInPost += 1;
					}
				}	
			}else { 
				//Als het veld leeg is return dan NULL (met als symbool dat de applicatie niet wordt verwijdert)
				out.println("NULL");
			}
//---------------------------------------------------------------------------------				
			
			//check of er geen fouten zitten in de meegegeven velden
			if(foutenInPost == 0) {
				out.println("<body style='background-color:green;'><br><br><h3><b>Post OK</b></h3>");
			}else {
				if(foutenInPost == 1) {
					out.println("<body style='background-color:red;'><br><br><h3><b>Er is " + foutenInPost + " fout! De Post is niet afgehandeld!</b></h3>");
				}
				if(foutenInPost > 1) {
					out.println("<body style='background-color:red;'><br><br><h3><b>Er zijn " + foutenInPost + " fouten! De Post is niet afgehandeld!</b></h3>");
				}
			}
		}else {	
			//Als de key net klopt geef dan een 401
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
		}

		
	}
	private Map<String, String> getHeadersInfo(HttpServletRequest request) {

        Map<String, String> map = new HashMap<String, String>();

        Enumeration headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            map.put(key, value);
        }

        return map;
    }
}
