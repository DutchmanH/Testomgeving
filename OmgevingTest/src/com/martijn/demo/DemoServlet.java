package com.martijn.demo;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

@WebServlet("/api/v2/applications/")
public class DemoServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	public DemoServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		PrintWriter out = response.getWriter();
		//Ophalen van de username/password/authentication vanuit de header
		Map headers = getHeadersInfo(request);
		String user = (String) headers.get("username");
		String pass = (String) headers.get("password");
	
		//--------------------------------------
		//---[access key validation endpoint]---
		//--------------------------------------
		// in de database ophalen: apikey van de gegeven app_id
		String api_Key = "ttn-account-v2.AsPgKrlBzptbiaXEtOsvX8qnvTHEC4GZPQlKlxKdWbg";
		
		//Ophalen key vanuit de header
		String auth = (String) headers.get("authorization");
		String key = auth.substring(3,auth.length());
		
		//check of de gegeven apikey klopt zo ja: 200 OK zo nee: 401
		if(key.trim().equals(api_Key)) {
			//Ophalen uit DB: rechten van de Applicatie
			List listRights = new ArrayList();
			listRights.add("\"messages:up:r\"");
			listRights.add("\"messages:down:w\"");
			listRights.add("\"devices\"");
			//Rechten printen
			out.println(listRights);
			//Status 200 OK
			response.setStatus(HttpServletResponse.SC_OK);
		}else {	
			//Als de key net klopt geef dan een 401
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
		}
		String testvenster = "uit"; //aan of uit
		if(testvenster.equals("aan")){
			out.println("<br><h1>--------------[Testvenster]---------------<h1><br>");
			out.println("<h2>Megestuurde Gegevens</h2>");
			out.println("<h3>In de URL</h3>");
			out.println("Username: <b>");
			out.println(request.getParameter("username"));
			out.println("<br></b>password:<b>");
			out.println(request.getParameter("password"));
			out.println("</b><br>");

			out.println("<h3>In de Header</h3>");
			out.println("Username: <b>");
			out.println(user);
			out.println("<br></b>password:<b>");
			out.println(pass);
			out.println("<br><h4></b>Authorization:<b>");
			out.println(auth);
			out.println("</b><br>key:<br>");
			out.println(key);
			out.println("<br><br>");
			out.println(getHeadersInfo(request));
		};
		
		
	
	
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
	
	

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

	
	


}
