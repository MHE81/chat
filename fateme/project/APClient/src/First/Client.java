package First;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;

public class Client {
    Socket mySocket;
    int port = 7030;
    String serverAddress = "127.0.0.1";
    InputStream fromServer;
    OutputStream toServer;
    DataInputStream reader;
    PrintWriter writer;
    ClientFXUI clientUIHolder = null;

    public Client(ClientFXUI clientUI){
        clientUIHolder = clientUI;
    }
    public Client(){}

    public void start(){
        try {
            mySocket = new Socket(serverAddress, port);
            System.out.println("Connect to Server...");
            fromServer = mySocket.getInputStream();
            toServer = mySocket.getOutputStream();
            reader = new DataInputStream(fromServer);
            writer = new PrintWriter(toServer, true);
            Thread t = new Thread(new ServerManager(reader, clientUIHolder));
            t.start();
        } catch (UnknownHostException e){
        } catch (IOException e){
            System.out.println(e.getMessage());
        }
    }

}
