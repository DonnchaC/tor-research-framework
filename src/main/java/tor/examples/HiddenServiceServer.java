/*
        Tor Research Framework - easy to use tor client library/framework
        Copyright (C) 2014  Dr Gareth Owen <drgowen@gmail.com>
        www.ghowen.me / github.com/drgowen/tor-research-framework

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package tor.examples;

import tor.*;

import java.io.*;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;


import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.Headers;

public class HiddenServiceServer {

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/", new GetHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }


    static class GetHandler implements HttpHandler {
        public void handle(HttpExchange httpExchange) throws IOException {
            Consensus con = Consensus.getConsensus();
            TorSocket sock = new TorSocket(con.getRandomORWithFlag("Guard,Fast,Running,Valid"));
            String postbody = null;

            if("POST".equalsIgnoreCase(httpExchange.getRequestMethod())) {
                // Treat as post request, uploading descriptor
                InputStreamReader isr = new InputStreamReader(httpExchange.getRequestBody(), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                postbody = org.apache.commons.io.IOUtils.toString(br);
            }
            Map<String, String> parms = HiddenServiceServer.queryToMap(httpExchange.getRequestURI().getQuery());

            StringBuilder response = new StringBuilder();
            try {
                if("POST".equalsIgnoreCase(httpExchange.getRequestMethod())) {
                    final String result = HiddenService.postHSDescriptor(sock, postbody, parms.get("fingerprint"));
                    response.append(result);
                } else {
                    final String descriptor = HiddenService.getHSDescriptor(sock, parms.get("descriptor"), parms.get("fingerprint"));
                    response.append(descriptor);
                }
                HiddenServiceServer.writeResponse(httpExchange, response.toString(), 200);
            } catch(IOException e) {
                if(e.getMessage().contains("HTTPError")) {
                    // Extract the response code from the HSDir and forward it to the client
                    response.append(e.getMessage().substring(e.getMessage().indexOf(e.getMessage().split(" ")[3])));
                    HiddenServiceServer.writeResponse(httpExchange, response.toString(),
                            (Integer.valueOf(e.getMessage().split(" ")[2])));
                } else {
                    // Some other error occurred, send the client the message
                    response.append(e.getMessage());
                    HiddenServiceServer.writeResponse(httpExchange, response.toString(), 500);
                }
            }
        }
    }

    public static void writeResponse(HttpExchange httpExchange, String response, Integer code) throws IOException {
        httpExchange.sendResponseHeaders(code, response.length());
        OutputStream os = httpExchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    /**
     * returns the url parameters in a map
     * @param query
     * @return map
     */
    public static Map<String, String> queryToMap(String query){
        Map<String, String> result = new HashMap<String, String>();
        for (String param : query.split("&")) {
            String pair[] = param.split("=");
            if (pair.length>1) {
                result.put(pair[0], pair[1]);
            }else{
                result.put(pair[0], "");
            }
        }
        return result;
    }

}
